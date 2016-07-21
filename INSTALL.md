# Installation

Right now this only works with Crowd version 2.7.2. There are incompatible API changes in 2.9.1 (latest).

# Steps

## Creating JAR files

Assuming Ubuntu 14.04, run the following commands as root:

```shell
apt-get install -y apt-transport-https
echo "deb https://sdkrepo.atlassian.com/debian/ stable contrib" >> /etc/apt/sources.list
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys B07804338C015B73
apt-get update
apt-get install -y atlassian-plugin-sdk

cd /root
git clone https://github.com/Eduix/crowd-shibboleth-module
cd crowd-shibboleth-module/shibboleth-filter-config
atlas-package
cp target/*.jar /opt/atlassian/crowd/crowd-webapp/WEB-INF/lib
cd ../shibboleth-filter
/usr/share/atlassian-plugin-sdk-6.2.8/apache-maven-3.2.1/bin/mvn install:install-file -DgroupId=com.eduix.crowd -DartifactId=shibboleth-filter-config -Dversion=1.1.1 -Dpackaging=jar -Dfile=/root/crowd-shibboleth-module/shibboleth-filter-config/target/shibboleth-filter-config-1.1.1.jar
atlas-package
cp target/*.jar /opt/atlassian/crowd/crowd-webapp/WEB-INF/lib
chown crowd: /opt/atlassian/crowd/crowd-webapp/WEB-INF/lib/*.jar
cd ~/crowd-shibboleth-module/nordunet-sso
atlas-package
cp target/*.jar /opt/atlassian/home/plugins/
chown crowd: /opt/atlassian/home/plugins/*
```

## Files

* Download `ShibbolethSSOFilter.properties`

```shell
cd /opt/atlassian/crowd/crowd-webapp/WEB-INF/classes
wget -O ShibbolethSSOFilter.properties https://raw.githubusercontent.com/Eduix/crowd-shibboleth-module/master/shibboleth-filter/src/main/resources/ShibbolethSSOFilter.example.properties
```

* Edit `applicationContext-CrowdSecurity.xml` by following the instructions in the `shibboleth-filter/README.TXT` file.
