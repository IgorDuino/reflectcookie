public class CookieInfo {
    private final String name;
    private final String domain;
    private final String path;
    private final boolean httpOnly;
    private final boolean secure;
    private final String sameSite;

    public CookieInfo(String name, String domain, String path, boolean httpOnly, boolean secure, String sameSite) {
        this.name = name;
        this.domain = domain;
        this.path = path;
        this.httpOnly = httpOnly;
        this.secure = secure;
        this.sameSite = sameSite;
    }

    public String getName() {
        return name;
    }

    public String getDomain() {
        return domain;
    }

    public String getPath() {
        return path;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

    public boolean isSecure() {
        return secure;
    }

    public String getSameSite() {
        return sameSite;
    }
}
