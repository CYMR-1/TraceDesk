"""TraceDesk MCP 服务端端到端测试（真实 TSK 流程、安全边界、Streamable HTTP 与 stdio 传输）。"""
import asyncio
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from forensic.core.case import Case
from forensic.mcp.runtime import LocalHttpMcpManager, validate_loopback_host
from forensic.mcp.server import TOOL_CATALOG, create_server
from forensic.paths import ROOT, TEST_WORK_DIR
from scripts.make_demo import create
from scripts.verify_bundle import verify_bundle as verify_bundle_zip
from tests.fixtures import create_multi_partition_image


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _extract_text(call_result) -> str:
    if isinstance(call_result, tuple):
        content = call_result[0]
    elif hasattr(call_result, 'content'):
        content = call_result.content
    else:
        content = call_result
    return '\n'.join(getattr(block, 'text', str(block)) for block in content)


class McpWorkflowTests(unittest.TestCase):
    def setUp(self):
        TEST_WORK_DIR.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=TEST_WORK_DIR)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cases_dir = self.root / 'cases'
        self.cases_dir.mkdir()
        self.image = self.root / 'evidence' / 'demo_mcp.dd'
        self.manifest = create(self.image)
        self.server = create_server(cases_root=self.cases_dir)

    def _call_json(self, tool_name: str, arguments: dict) -> dict:
        payload = {'params': {**arguments, 'response_format': 'json'}}
        raw = asyncio.run(self.server.call_tool(tool_name, payload))
        text = _extract_text(raw)
        self.assertFalse(text.startswith('Error ('), text)
        return json.loads(text)

    def _call_text(self, tool_name: str, arguments: dict) -> str:
        raw = asyncio.run(self.server.call_tool(tool_name, {'params': arguments}))
        return _extract_text(raw)

    def test_tool_catalog_matches_registered_fastmcp_tools(self):
        tools = asyncio.run(self.server.list_tools())
        self.assertEqual([t.name for t in tools], [item['name'] for item in TOOL_CATALOG])
        resources = asyncio.run(self.server.list_resources())
        self.assertEqual({str(r.uri) for r in resources}, {'tracedesk://cases', 'tracedesk://guide/workflow'})

    def test_full_real_tsk_forensic_workflow_via_mcp_tools(self):
        created = self._call_json(
            'tracedesk_create_case',
            {'number': 'MCP-001', 'examiner': '张取证', 'target': 'FAT16 演示镜像'},
        )
        case_dir = created['case_dir']
        self.assertTrue((Path(case_dir) / 'case.json').is_file())

        listed = self._call_json('tracedesk_list_cases', {})
        self.assertEqual(listed['total'], 1)
        self.assertEqual(listed['items'][0]['number'], 'MCP-001')

        loaded = self._call_json(
            'tracedesk_load_image',
            {'case_dir': case_dir, 'image_path': str(self.image), 'scan_all': True},
        )
        self.assertTrue(loaded['scanned_all_partitions'])
        self.assertGreater(loaded['inventory_count'], 0)
        image_sha = loaded['sha256']
        self.assertEqual(len(image_sha), 64)

        registered = self._call_json(
            'tracedesk_register_source',
            {
                'case_dir': case_dir,
                'evidence_id': 'EV-01',
                'source': '教学实验室',
                'acquired': '2026-09-01 08:00 UTC+8',
                'tool': 'make_demo',
                'expected_sha256': image_sha,
            },
        )
        self.assertIn('一致', registered['source_comparison'])

        verified = self._call_json('tracedesk_verify_integrity', {'case_dir': case_dir})
        self.assertTrue(verified['ok'])

        summary_md = self._call_text('tracedesk_get_case_summary', {'case_dir': case_dir})
        self.assertIn('MCP-001', summary_md)
        self.assertIn(image_sha, summary_md)

        files = self._call_json(
            'tracedesk_list_files',
            {'case_dir': case_dir, 'suffix': 'txt', 'keyword': 'case', 'files_only': True},
        )
        self.assertEqual(files['total'], 1)
        case_txt = files['items'][0]
        self.assertEqual(case_txt['path'], 'DOCS/CASE.TXT')
        self.assertEqual(case_txt['partition_offset'], 2048)

        preview = self._call_json(
            'tracedesk_preview_file',
            {
                'case_dir': case_dir,
                'path': 'DOCS/CASE.TXT',
                'partition_offset': 2048,
                'inode': case_txt['inode'],
                'encoding': 'UTF-8',
                'mode': 'both',
            },
        )
        self.assertIn('Case note inside a nested directory.', preview['text'])
        self.assertTrue(preview['hex_lines'][0].startswith('00000000  43 61 73 65'))

        search_hex = self._call_json(
            'tracedesk_search_content',
            {
                'case_dir': case_dir,
                'query': '6E 6F 74 65',
                'encoding': 'HEX',
                'path': 'DOCS/CASE.TXT',
                'partition_offset': 2048,
            },
        )
        self.assertEqual(search_hex['total'], 1)
        self.assertEqual(search_hex['items'][0]['file_byte'], 5)

        exported = self._call_json(
            'tracedesk_export_file',
            {'case_dir': case_dir, 'path': 'DOCS/CASE.TXT', 'partition_offset': 2048},
        )
        exported_path = Path(exported['exported_path'])
        self.assertTrue(exported_path.is_file())
        self.assertEqual(exported['record']['sha256'], self.manifest['DOCS/CASE.TXT']['sha256'])

        compared = self._call_json(
            'tracedesk_examine_file',
            {
                'case_dir': case_dir,
                'path': 'DOCS/CASE.TXT',
                'partition_offset': 2048,
                'comparison_path': str(exported_path),
            },
        )
        self.assertEqual(compared['result'], '一致')

        noted = self._call_json(
            'tracedesk_record_finding',
            {
                'case_dir': case_dir,
                'path': 'DOCS/CASE.TXT',
                'partition_offset': 2048,
                'note': '文件内偏移 5 处包含字节 6E 6F 74 65 (note)',
            },
        )
        self.assertEqual(noted['actor'], '张取证')
        self.assertEqual(noted['origin'], 'mcp')
        self.assertEqual(noted['origin_label'], 'MCP')

        findings = self._call_json('tracedesk_list_findings', {'case_dir': case_dir, 'keyword': '6E 6F 74 65'})
        self.assertEqual(findings['total'], 1)
        self.assertEqual(findings['items'][0]['path'], 'DOCS/CASE.TXT')
        self.assertEqual(findings['items'][0]['records'][-1]['origin_label'], 'MCP')

        exported_findings = self._call_json('tracedesk_export_findings', {'case_dir': case_dir})
        self.assertEqual(exported_findings['exported_count'], 1, exported_findings)
        self.assertTrue(Path(exported_findings['summary_path']).is_file())

        timeline = self._call_json(
            'tracedesk_query_timeline',
            {'case_dir': case_dir, 'event': 'M', 'query': 'CASE.TXT'},
        )
        self.assertGreaterEqual(timeline['total'], 1)
        self.assertEqual(timeline['items'][0]['event'], 'M 内容修改')

        # 补充一条人工操作，验证同一案件中人工与 MCP 审计日志能严格区分与筛选
        manual_case = Case(case_dir)
        try:
            manual_case.verify()
        finally:
            manual_case.close()

        audit_mcp = self._call_json(
            'tracedesk_query_audit_log',
            {'case_dir': case_dir, 'origin': 'mcp', 'sort_order': 'desc'},
        )
        self.assertTrue(audit_mcp['audit_chain_valid'])
        self.assertGreaterEqual(audit_mcp['total'], 5)
        self.assertTrue(all(item['origin'] == 'mcp' and item['origin_label'] == 'MCP' for item in audit_mcp['items']))
        self.assertEqual(audit_mcp['origin_counts']['manual'], 1)
        self.assertEqual(audit_mcp['origin_counts']['mcp'], audit_mcp['total'])

        audit_manual = self._call_json(
            'tracedesk_query_audit_log',
            {'case_dir': case_dir, 'origin': 'manual'},
        )
        self.assertEqual(audit_manual['total'], 1)
        self.assertEqual(audit_manual['items'][0]['origin'], 'manual')
        self.assertEqual(audit_manual['items'][0]['origin_label'], '人工')
        self.assertEqual(audit_manual['items'][0]['action'], 'HASH_VERIFY')

        audit_md = self._call_text('tracedesk_query_audit_log', {'case_dir': case_dir})
        self.assertIn('[MCP]', audit_md)
        self.assertIn('[人工]', audit_md)

        report = self._call_json('tracedesk_generate_report', {'case_dir': case_dir})
        report_path = Path(report['report_path'])
        self.assertTrue(report_path.is_file())
        report_text = report_path.read_text(encoding='utf-8')
        self.assertIn('6E 6F 74 65', report_text)
        self.assertIn('| 序号 | 时间 (UTC+8) | 来源 | 操作人员 | 操作 | 对象 | 结果 |', report_text)
        self.assertIn('| 人工 |', report_text)
        self.assertIn('| MCP |', report_text)

        # 验证篡改 audit.jsonl 中的 origin（例如把 MCP 伪造成 manual）会被审计哈希链检测拦截
        bundle = self._call_json('tracedesk_build_review_bundle', {'case_dir': case_dir})
        bundle_path = Path(bundle['bundle_path'])
        self.assertTrue(bundle_path.is_file())
        verify_bundle_zip(bundle_path, bundle['sha256'])

        audit_file = Path(case_dir) / 'audit.jsonl'
        tampered = audit_file.read_text(encoding='utf-8').replace('"origin":"mcp"', '"origin":"manual"', 1)
        audit_file.write_text(tampered, encoding='utf-8')
        tamper_err = self._call_text('tracedesk_query_audit_log', {'case_dir': case_dir})
        self.assertIn('不完整或被修改', tamper_err)

    def test_boundaries_and_lock_contention_return_actionable_errors(self):
        created = self._call_json(
            'tracedesk_create_case',
            {'number': 'MCP-LOCK', 'examiner': '测试员', 'target': '边界验证'},
        )
        case_dir = created['case_dir']

        # 源镜像位于案件库目录内必须被拒绝
        bad_image = self.cases_dir / 'inside.dd'
        bad_image.write_bytes(b'\x00' * 512)
        err = self._call_text(
            'tracedesk_load_image',
            {'case_dir': case_dir, 'image_path': str(bad_image)},
        )
        self.assertIn('Error (ValueError)', err)
        self.assertIn('案件库目录之外', err)

        # 桌面端持有 case.lock 时返回可操作提示，而不是崩溃
        opened = Case(case_dir)
        self.addCleanup(opened.close)
        lock_err = self._call_text('tracedesk_get_case_summary', {'case_dir': case_dir})
        self.assertIn('锁定', lock_err)
        self.assertIn('桌面端', lock_err)

        # 非回环监听地址必须被拒绝
        with self.assertRaisesRegex(ValueError, '回环'):
            validate_loopback_host('0.0.0.0')

    def test_multi_partition_disambiguation_deleted_files_and_resources(self):
        multi_image = self.root / 'evidence' / 'multi.dd'
        create_multi_partition_image(multi_image)
        # 将第一分区根目录第二条记录（NOTES.TXT）首字节改为 0xE5 以构造真实 FAT16 删除记录
        raw = bytearray(multi_image.read_bytes())
        root_dir_offset = (2048 + 1 + 2 * 64) * 512
        raw[root_dir_offset + 32] = 0xE5
        multi_image.write_bytes(raw)
        created = self._call_json(
            'tracedesk_create_case',
            {'number': 'MCP-MULTI', 'examiner': '测试员', 'target': '多分区与删除恢复'},
        )
        case_dir = created['case_dir']
        self._call_json(
            'tracedesk_load_image',
            {'case_dir': case_dir, 'image_path': str(multi_image), 'scan_all': False},
        )
        scanned = self._call_json('tracedesk_scan_partitions', {'case_dir': case_dir})
        self.assertEqual(len(scanned['partition_scans']), 2)

        # 不提供 partition_offset 时，跨分区同名文件应返回明确的歧义提示
        ambiguous = self._call_text('tracedesk_preview_file', {'case_dir': case_dir, 'path': 'README.TXT'})
        self.assertIn('歧义', ambiguous)
        self.assertIn('2048', ambiguous)
        self.assertIn('20480', ambiguous)

        # 提供 partition_offset=20480 时精准读取第二分区内容
        p2 = self._call_json(
            'tracedesk_preview_file',
            {'case_dir': case_dir, 'path': 'README.TXT', 'partition_offset': 20480, 'mode': 'text'},
        )
        self.assertTrue(p2['text'].startswith('SECOND FS'))

        # 验证已删除文件筛选与预览
        deleted_list = self._call_json(
            'tracedesk_list_files',
            {'case_dir': case_dir, 'partition_offset': 2048, 'status': 'deleted', 'files_only': True},
        )
        self.assertGreaterEqual(deleted_list['total'], 1)
        deleted_entry = deleted_list['items'][0]
        deleted_preview = self._call_json(
            'tracedesk_preview_file',
            {
                'case_dir': case_dir,
                'path': deleted_entry['path'],
                'partition_offset': 2048,
                'inode': deleted_entry['inode'],
                'deleted': True,
                'mode': 'text',
            },
        )
        self.assertTrue(deleted_preview['entry']['deleted'])

        # 验证 MCP 资源可读
        guide_res = asyncio.run(self.server.read_resource('tracedesk://guide/workflow'))
        self.assertIn('tracedesk_load_image', _extract_text(guide_res))
        cases_res = asyncio.run(self.server.read_resource('tracedesk://cases'))
        self.assertIn('MCP-MULTI', _extract_text(cases_res))

    def test_streamable_http_transport_end_to_end(self):
        created = self._call_json(
            'tracedesk_create_case',
            {'number': 'MCP-HTTP', 'examiner': '测试员', 'target': 'HTTP 传输'},
        )
        port = _free_local_port()
        manager = LocalHttpMcpManager(cases_root=self.cases_dir)
        url = manager.start(host='127.0.0.1', port=port, path='/mcp')
        self.addCleanup(manager.stop)
        self.assertTrue(manager.running)

        async def client_check():
            async with streamable_http_client(url) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual(len(tools.tools), len(TOOL_CATALOG))
                    result = await session.call_tool(
                        'tracedesk_list_cases',
                        {'params': {'response_format': 'json'}},
                    )
                    data = json.loads(_extract_text(result))
                    self.assertEqual(data['total'], 1)
                    self.assertEqual(data['items'][0]['case_dir' if 'case_dir' in data['items'][0] else 'folder'], created['case_dir'])

        asyncio.run(client_check())
        manager.stop()
        self.assertFalse(manager.running)

    def test_stdio_transport_end_to_end(self):
        self._call_json(
            'tracedesk_create_case',
            {'number': 'MCP-STDIO', 'examiner': '测试员', 'target': 'STDIO 传输'},
        )
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / 'mcp_server.py'), '--cases-dir', str(self.cases_dir)],
            cwd=str(ROOT),
        )

        async def client_check():
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual(len(tools.tools), len(TOOL_CATALOG))
                    resources = await session.list_resources()
                    self.assertGreaterEqual(len(resources.resources), 2)
                    result = await session.call_tool(
                        'tracedesk_list_cases',
                        {'params': {'response_format': 'json'}},
                    )
                    data = json.loads(_extract_text(result))
                    self.assertEqual(data['total'], 1)
                    self.assertEqual(data['items'][0]['number'], 'MCP-STDIO')

        asyncio.run(client_check())


if __name__ == '__main__':
    unittest.main()
