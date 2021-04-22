package burp.Util;

import burp.IInterceptedProxyMessage;

public interface ProxyHandler {
    void handle(boolean messageIsRequest, IInterceptedProxyMessage message);
}