package burp;

import java.awt.Component;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Reader;

import javax.swing.JSplitPane;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import burp.Util.ProxyListener;
import burp.autologin.AutoLogin;
import burp.autologin.core.AutoLoginItem;
import burp.jsonbeautify.JsonTab;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, ITab, IExtensionStateListener {
    static public IBurpExtenderCallbacks callbacks;
    static public IExtensionHelpers helpers;
    public static PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // TODO Auto-generated method stub

        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();
        BurpExtender.stderr = new PrintWriter(callbacks.getStderr(), true);

        System.setErr(new PrintStream(callbacks.getStderr(), true));
        System.setOut(new PrintStream(callbacks.getStdout(), true));

        BurpExtender.callbacks.setExtensionName("AutoLogin");
        BurpExtender.callbacks.registerMessageEditorTabFactory(this);
        BurpExtender.callbacks.addSuiteTab(this);
        BurpExtender.callbacks.registerProxyListener(ProxyListener.getProxyListener());
        BurpExtender.callbacks.registerExtensionStateListener(this);
        BurpExtender.callbacks.registerContextMenuFactory(AutoLogin.getInstance());
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // TODO Auto-generated method stub
        return new JsonTab();
    }

    @Override
    public String getTabCaption() {
        // TODO Auto-generated method stub
        return "AutoLogin";
    }

    @Override
    public Component getUiComponent() {
        // TODO Auto-generated method stub
        return AutoLogin.getInstance();
    }

    @Override
    public void extensionUnloaded() {
        // TODO Auto-generated method stub
        AutoLogin.getInstance().saveConfig();
    }

    
}