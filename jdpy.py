import os
import subprocess
import sys
import hashlib
import time
import shutil
from datetime import datetime
import json

# 默认白名单 - 常见Java库，通常不需要反编译
DEFAULT_WHITELIST = [
    # Java标准库
    "rt.jar", "jrt-fs.jar", "java-atk-wrapper.jar", "bootstrap.jar", "tomcat-juli",
    
    # 常见Apache Commons库
    "commons-lang", "commons-io", "commons-codec", "commons-collections", 
    "commons-compress", "commons-cli", "commons-dbcp", "commons-pool",
    "commons-fileupload", "commons-validator", "commons-net", "commons-email",
    "commons-daemon", "commons-beanutils", "commons-digester", "commons-discovery",
    "commons-jexl", "commons-math", "commons-text", "commons-csv",
    "commons-logging-api",
    
    # Spring框架相关库 - 扩展
    "spring-core", "spring-beans", "spring-context", "spring-web", 
    "spring-webmvc", "spring-boot", "spring-boot-autoconfigure",
    "spring-aop", "spring-aspects", "spring-expression", "spring-instrument",
    "spring-jdbc", "spring-jms", "spring-messaging", "spring-orm",
    "spring-oxm", "spring-test", "spring-tx", "spring-websocket",
    "spring-data-commons", "spring-data-jpa", "spring-data-mongodb",
    "spring-data-redis", "spring-data-solr", "spring-data-rest",
    "spring-security", "spring-session", "spring-batch", "spring-integration",
    "spring-hateoas", "spring-mobile", "spring-social", "spring-ws",
    "spring-cloud", "spring-boot-starter",
    
    # AspectJ
    "aspectjrt", "aspectjweaver", "aspectjtools",
    
    # 数据库驱动
    "mysql-connector", "postgresql", "h2-", "ojdbc", "sqlite-jdbc", "mariadb-java-client",
    "mssql-jdbc", "db2jcc", "derby", 
    
    # Hibernate & JPA
    "hibernate-core", "hibernate-entitymanager", "hibernate-validator", "jpa-api",
    "javax.persistence", "jboss-logging", "javassist", "jandex", "classmate",
    "hibernate-commons-annotations", "hibernate-jpa",
    
    # MyBatis
    "mybatis", "mybatis-spring", 
    
    # 日志库
    "log4j", "slf4j", "logback", "commons-logging", "log4j-api", "log4j-core",
    "jcl-over-slf4j", "jul-to-slf4j", "log4j-over-slf4j",
    
    # JSON库
    "jackson-core", "jackson-databind", "jackson-annotations", "gson", "json-simple",
    "fastjson", "org.json", 
    
    # XML处理
    "dom4j", "jaxb", "xstream", "jdom", "saxon", "xerces", "xml-apis", "xmlbeans",
    
    # 解析器相关
    "antlr", "asm", "cglib", "groovy", "javacc", "jaxen", "bcel",
    
    # 网络和HTTP库
    "httpclient", "httpcore", "httpmime", "okhttp", "netty", "jetty", "tomcat-embed", 
    "undertow", "grizzly", "jersey", "cxf", "axis", "resteasy", "activemq", "rabbitmq",
    "websocket", "mina", "jgroups", "tomcat-jdbc", "tomcat-embed",
    
    # 常见工具库
    "guava", "lombok", "joda-time", "commons-lang3", "jaxrs-api", "validation-api",
    "javax.annotation", "javax.inject", "javax.activation", "javax.mail", "activation",
    "jsr305", "icu4j", "ehcache", "quartz", "cron4j", "jsch", "jzlib",
    "snakeyaml", "bridge-method-annotation", "mysema-commons",
    
    # 安全相关
    "bcprov", "shiro", "jasypt", "not-yet-commons-ssl", "oauth", "keycloak", "jwt",
    "nimbus-jose", "passay", "owasp", "bouncy", "opensaml", "jjwt",
    
    # 模板引擎
    "freemarker", "velocity", "thymeleaf", "mustache", "jsoup",
    
    # 测试库
    "junit", "mockito", "testng", "hamcrest", "assertj", "easymock", "jmock", "powermock",
    "cucumber", "selenium", "appium", "rest-assured", "wiremock", "jbehave",
    
    # Java EE / Jakarta EE
    "javax.", "jakarta.", "jsf-api", "jsf-impl", "jstl", "el-api", "el-impl",
    "jsp-api", "servlet-api", "tomcat-annotations", "jta", "mail", "javax.transaction",
    "jboss-jaxrs", "jboss-servlet-api", "javaee-api", "jboss-javaee",
    
    # 查询相关
    "querydsl", "jooq", "eclipselink",
    
    # Web相关
    "ckeditor", "urlrewritefilter", "sitemesh", "displaytag", "zxing",
    
    # 其他常见库
    "activation", "avalon", "batik", "bsh", "c3p0", "jcl", "jcommon", "jdom", 
    "jfreechart", "jibx", "jmf", "jtidy", "lucene", "oro", "poi", "regexp",
    "saaj", "standard", "stax", "taglibs", "velocity", "wsdl4j", "xalan", "xpp",
    "bcel", "juel", "smack", "commons-httpclient", "jsf", "geronimo", "eclipselink",
    "fluent-hc", "jedis", "jna", "kryo", "protobuf", "snappy", "woodstox",
    "jboss-transaction", "jboss-j2ee", "jboss-vfs", "concurrent"
]

def load_whitelist(whitelist_file=None):
    """Load whitelist from file or use default"""
    whitelist = DEFAULT_WHITELIST.copy()
    
    if whitelist_file and os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r') as f:
                custom_whitelist = json.load(f)
                whitelist.extend(custom_whitelist)
                print(f"Loaded {len(custom_whitelist)} additional entries from whitelist file")
        except Exception as e:
            print(f"Error loading whitelist file: {str(e)}")
    
    return whitelist

def is_whitelisted(jar_name, whitelist):
       """Check if JAR is in whitelist (should be skipped)"""
       jar_lower = jar_name.lower()
       for entry in whitelist:
           if entry.lower() in jar_lower:
               return True
       return False

def calculate_jar_hash(jar_path):
    """Calculate MD5 hash of JAR file to detect changes"""
    hash_md5 = hashlib.md5()
    with open(jar_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def decompile_jar_with_cfr(jar_file_path, jar_output_dir, cfr_path):
    """Decompile JAR file using CFR decompiler"""
    try:
        os.makedirs(jar_output_dir, exist_ok=True)
        subprocess.run(
            ['java', '-jar', cfr_path, jar_file_path, '--outputdir', jar_output_dir],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"Error decompiling with CFR: {jar_file_path}: {e}")
        return False

def decompile_jar_with_procyon(jar_file_path, jar_output_dir, procyon_path):
    """Decompile JAR file using Procyon as fallback"""
    try:
        os.makedirs(jar_output_dir, exist_ok=True)
        subprocess.run(
            ['java', '-jar', procyon_path, '-o', jar_output_dir, jar_file_path],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"Error decompiling with Procyon: {jar_file_path}: {e}")
        return False

def decompile_jar(jar_file_path, jar_output_dir, cfr_path, procyon_path, cache_dir, whitelist):
    """Decompile a single JAR file with caching and whitelist check"""
    jar_name = os.path.basename(jar_file_path)
    
    # Check if JAR is in whitelist (should be skipped)
    if is_whitelisted(jar_name, whitelist):
        print(f"Skipping {jar_name} (in whitelist)")
        return True
    
    jar_hash = calculate_jar_hash(jar_file_path)
    cache_file = os.path.join(cache_dir, f"{jar_name}_{jar_hash}.decompiled")
    
    # Skip if cache exists (JAR already processed and unchanged)
    if os.path.exists(cache_file):
        print(f"Skipping {jar_name} (already decompiled)")
        return True
    
    # Clean output directory if exists
    if os.path.exists(jar_output_dir):
        shutil.rmtree(jar_output_dir)
    
    # Try to decompile with CFR first, then fall back to Procyon if needed
    decompile_success = decompile_jar_with_cfr(jar_file_path, jar_output_dir, cfr_path)
    
    if not decompile_success and procyon_path:
        print(f"Trying fallback decompiler for {jar_name}")
        decompile_success = decompile_jar_with_procyon(jar_file_path, jar_output_dir, procyon_path)
    
    if decompile_success:
        # Create cache record if successful
        with open(cache_file, 'w') as f:
            f.write(f"Decompiled on {datetime.now()}")
        return True
    else:
        print(f"All decompilation attempts failed for {jar_name}")
        return False

def decompile_jars(directory, cfr_path, procyon_path, output_dir, whitelist_file=None):
    """Decompile all JAR files in a directory"""
    start_time = time.time()
    
    # Load whitelist
    whitelist = load_whitelist(whitelist_file)
    print(f"Whitelist contains {len(whitelist)} entries")
    
    # Create output and cache directories
    os.makedirs(output_dir, exist_ok=True)
    cache_dir = os.path.join(output_dir, "cache")
    os.makedirs(cache_dir, exist_ok=True)
    
    # Collect all JAR files
    jar_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.jar'):
                jar_files.append(os.path.join(root, file))
    
    total_jars = len(jar_files)
    print(f"Found {total_jars} JAR files to process")
    
    # Process each JAR sequentially
    processed = 0
    successful = 0
    failed = 0
    skipped = 0
    
    for jar_path in jar_files:
        jar_name = os.path.basename(jar_path)
        print(f"Processing {jar_name} ({processed+1}/{total_jars})")
        
        jar_output_dir = os.path.join(output_dir, f"jar_{jar_name}")
        
        try:
            # Check if JAR is in whitelist before full processing
            if is_whitelisted(jar_name, whitelist):
                print(f"Skipping {jar_name} (in whitelist)")
                skipped += 1
                processed += 1
                continue
                
            success = decompile_jar(
                jar_path, jar_output_dir, cfr_path, procyon_path, cache_dir, whitelist
            )
            
            if success:
                successful += 1
            else:
                failed += 1
                
        except Exception as e:
            print(f"Error processing {jar_path}: {str(e)}")
            failed += 1
        
        processed += 1
        print(f"Progress: {processed}/{total_jars} ({processed/total_jars*100:.1f}%)")
    
    elapsed_time = time.time() - start_time
    print(f"Completed in {elapsed_time:.2f} seconds")
    print(f"Results: Total: {total_jars}, Successful: {successful}, Failed: {failed}, Skipped: {skipped}")
    print(f"All decompiled files are available in: {os.path.abspath(output_dir)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decompile_jars.py <directory> <output_directory> [whitelist_file]")
        sys.exit(1)

    search_directory = sys.argv[1]
    #output_dir = sys.argv[2]
    whitelist_file = None
    #whitelist_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Configure decompiler paths - replace these with actual paths
    cfr_path = "/root/jd-cli/cfr-0.152.jar"  # Primary decompiler
    procyon_path = "/root/jd-cli/procyon-decompiler-0.6.0.jar"  # Fallback decompiler
    output_dir = "./decompiled_output"
    
    decompile_jars(search_directory, cfr_path, procyon_path, output_dir, whitelist_file)
