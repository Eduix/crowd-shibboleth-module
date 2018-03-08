# Installation

This version works only with Crowd 3.0+ due to API changes.

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

## Apache Shibboleth Module

* Require Shibboleth authentication on the `ssocookie` servlet:

```
<Location /crowd/plugins/servlet/ssocookie>
  AuthType shibboleth
  Require shibboleth
  ShibUseHeaders on
  ShibRequestSetting requireSession 1
</Location>
```

* Ensure the Shibboleth module is getting a `REMOTE_USER` setting.
* Configure your `attribute-map.xml` appropriately.

## Enabling

* Locate the source to an Atlassian-compatible login page. For example, the Crowd demo app login page is located at `/opt/atlassian/crowd/demo-webapp/login.jsp`.
* Add a link to login with Shibboleth. For example:

```
<p>Login with <a href="https://example.com/crowd/plugins/servlet/ssocookie?redirectTo=%2fdemo%2Fsecure%2Fconsole%2Fconsole.action">Shibboleth</a></p>
```
