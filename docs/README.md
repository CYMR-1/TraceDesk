# 文档导航

| 想了解什么 | 阅读位置 |
| --- | --- |
| 启动、环境配置、编译运行、大容量镜像与 MCP 接入 | [项目 README](../README.md) |
| 文件放在哪里、增删功能、按任务查找代码与常用命令 | [目录结构与维护指南](目录结构.md) |
| 架构设计、界面规范、需求对应、案件格式、MCP 与取证边界 | [设计与验收说明](设计与验收说明.md) |
| Rust (`--release`) vs Python 3.13 性能对比与兼容实测 | [Rust 迁移性能对比实测](validation/Rust迁移性能对比实测.md) |
| 大容量镜像性能实测（1 TiB RAW / 50 GiB E01） | [1TiB 镜像性能实测](validation/1TiB镜像性能实测.md) |
| 分段 EWF 加载、浏览与复核实测 | [EWF 加载与复核实测](validation/EWF加载与复核实测.md) |
| 历史回归测试输出归档 | [测试结果](validation/test-results.txt) |

`validation/` 存放实测与验证记录。演示运行位置、错误日志等机器相关信息写入项目 `logs/`，不写入文档目录。
