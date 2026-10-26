# Fix for CVE-2017-12615

This folder contains the two configuration files of the vulnerable environment
**after** the fix, so that the change can be reviewed without rebuilding the whole
Vulhub repository.

## What the vulnerable image did

The original `Dockerfile` inserted the dangerous parameter into Tomcat's `conf/web.xml`
at build time:

```dockerfile
FROM vulhub/tomcat:8.5.19

LABEL maintainer="phithon <root@leavesongs.com>"

RUN cd /usr/local/tomcat/conf \
    && LINE=$(nl -ba web.xml | grep '<load-on-startup>1' | awk '{print $1}') \
    && ADDON="<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>" \
    && sed -i "$LINE i $ADDON" web.xml
```

`readonly=false` makes the `DefaultServlet` accept `PUT` requests, so a request to
`PUT /1.jsp/` writes a JSP file into the web root, which Tomcat then compiles and
executes.

## What was changed

| File | Change | Reason |
|---|---|---|
| `Dockerfile` | the `RUN` block above was deleted | Tomcat keeps its default `readonly=true`, so `PUT` is refused |
| `docker-compose.yml` | port published as `127.0.0.1:8080:8080` instead of `8080:8080` | the deliberately vulnerable service stays reachable from this machine only, not from the campus network |

The image base version (`8.5.19`) was **not** changed. The vulnerability depends on the
configuration, so the configuration is the fix; a version upgrade alone would leave the
parameter in place.

## How to apply

```bash
cd vulhub/tomcat/CVE-2017-12615
# replace Dockerfile and docker-compose.yml with the copies in this folder
docker compose down
docker compose build --no-cache
docker compose up -d --force-recreate
```

## How the fix was verified

| Check | Command | Expected | Observed |
|---|---|---|---|
| configuration | `docker compose exec tomcat grep -n readonly /usr/local/tomcat/conf/web.xml` | no active parameter | only an XML comment |
| same attack | `curl -X PUT .../1.jsp/` with the same payload | rejected | `403 Forbidden` |
| backdoor | `curl .../1.jsp` | gone | `404` |
| regression | open `http://localhost:8080` | page loads | default Tomcat page |

Screenshots: `docs/w1-05-fix-403.png`, `docs/w1-06-config-fixed.png`,
`docs/w1-07-regression-ok.png`.
