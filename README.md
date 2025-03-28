# jdpy

**java反编译辅助工具**

> 使用场景：有大量jar文件需要反编译

1. 可避免重复反编译
2. 采用白名单列表常见的java 库不反编译

需要如下两个反编译工具支持：
`cfr_path = "/root/jd-cli/cfr-0.152.jar"  # Primary decompiler`
`procyon_path = "/root/jd-cli/procyon-decompiler-0.6.0.jar"  # Fallback decompiler`

使用上面两个技术可以大大的缩减反编译项目的速度





