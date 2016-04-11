package org.fao.geonet.kernel.security.cda;

/**
 * Created by a614803 on 30/09/2015.
 */
public class CdaConfiguration {
    private String uri;

    private String proxyUrl;
    private Integer proxyPort;

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public Integer getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    public String getProxyUrl() {
        return proxyUrl;
    }

    public void setProxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
    }
}
