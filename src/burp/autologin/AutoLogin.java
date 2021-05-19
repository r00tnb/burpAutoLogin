package burp.autologin;

import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.table.TableModel;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.Util.ProxyHandler;
import burp.Util.ProxyListener;
import burp.Util.Util;
import burp.autologin.UI.*;
import burp.autologin.core.*;
import burp.autologin.core.Session.LoginProcessor;
import burp.autologin.core.Session.Token;
import burp.autologin.core.TokenReplaceModel.TokenReplace;
import jsoncomp.json.JSONParser;
import jsoncomp.json.jsonstyle.JsonArray;
import jsoncomp.json.jsonstyle.JsonObject;
import jsoncomp.json.parser.Parser;

public final class AutoLogin extends JSplitPane implements ProxyHandler, IContextMenuFactory {

    private static AutoLogin autoLogin;
    private static String name = "AutoLogin";

    public static AutoLogin getInstance() {
        if (autoLogin == null)
            autoLogin = new AutoLogin();

        return autoLogin;
    }

    private InfoTable table;

    private AutoLogin() {
        // init table
        this.table = new InfoTable();
        table.setFillsViewportHeight(true);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // TODO Auto-generated method stub
                if (e.getButton() == MouseEvent.BUTTON1 && table.getSelectedRowCount() > 0) {
                    setRightComponent(new SettingPanel(table.getSelectedItem()));
                } else if (e.isMetaDown()) {
                    JPopupMenu menu = new JPopupMenu();
                    JMenuItem addNewItem = new JMenuItem(Util.l("add new item"));
                    JMenuItem deleteItem = new JMenuItem(Util.l("delete seleted items"));
                    JMenuItem copyItem = new JMenuItem(Util.l("copy seleted items"));

                    menu.add(addNewItem);
                    addNewItem.addActionListener(new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            // TODO Auto-generated method stub
                            table.addRow(new AutoLoginItem());
                            table.setRowSelectionInterval(table.getRowCount() - 1, table.getRowCount() - 1);
                            setRightComponent(new SettingPanel(table.getSelectedItem()));
                        }

                    });
                    if (table.getSelectedRowCount() > 0) {
                        menu.add(deleteItem);
                        menu.add(copyItem);

                        deleteItem.addActionListener(new ActionListener() {

                            @Override
                            public void actionPerformed(ActionEvent e) {
                                // TODO Auto-generated method stub
                                if (JOptionPane.showConfirmDialog(AutoLogin.this,
                                        Util.l("are you sure?it will remove all info of the item")) != 0)
                                    return;
                                table.removeSelectedRows();
                            }

                        });

                        copyItem.addActionListener(new ActionListener() {

                            @Override
                            public void actionPerformed(ActionEvent e) {
                                List<AutoLoginItem> items = table.getSelectedItems();
                                for (AutoLoginItem item : items) {
                                    AutoLoginItem tmp = AutoLoginItem.fromJsonObject(AutoLoginItem.toJsonObject(item));
                                    tmp.setName(Util.randomString(8));
                                    tmp.setEnabled(false);
                                    table.addRow(tmp);
                                }
                            }

                        });
                    }

                    menu.show(table, e.getX(), e.getY());
                }
            }
        });

        try {
            loadConfig();
        } catch (Exception e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        if (table.getRowCount() == 0) {
            // 添加默认自动登录
            try {
                JsonArray itemArray = (JsonArray) new JSONParser()
                        .fromJSON(Util.getStringFromFile("/burp/autologin/resources/default_config.json"));
                for (Iterator<Object> iterator = itemArray.iterator(); iterator.hasNext();) {
                    AutoLoginItem item = AutoLoginItem.fromJsonObject((JsonObject) iterator.next());
                    table.addRow(item);
                }
                table.setRowSelectionInterval(0, 0);
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        } else {
            table.setRowSelectionInterval(0, 0);
        }

        setLeftComponent(new JScrollPane(table));
        setRightComponent(new SettingPanel(table.getSelectedItem()));

        ProxyListener.getProxyListener().addHandler(this);

    }

    public void saveConfig() {
        String name = "AutoLogin";
        JsonArray config = new JsonArray();
        for (AutoLoginItem item : table.getItemList()) {
            config.push(AutoLoginItem.toJsonObject(item));
        }

        BurpExtender.callbacks.saveExtensionSetting(name, config.toString());
    }

    public void loadConfig() throws Exception {
        String name = "AutoLogin";
        JSONParser parser = new JSONParser();
        JsonArray config = (JsonArray) parser.fromJSON(BurpExtender.callbacks.loadExtensionSetting(name));
        table.removeRowAll();
        for (Iterator<Object> iterator = config.iterator(); iterator.hasNext();) {
            JsonObject itemObject = (JsonObject) iterator.next();
            AutoLoginItem item = AutoLoginItem.fromJsonObject(itemObject);
            table.addRow(item);
        }
        if (table.getRowCount() > 0)
            table.setRowSelectionInterval(0, 0);
    }

    @Override
    public void handle(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // TODO Auto-generated method stub
        if (messageIsRequest)
            return;
        IHttpRequestResponse requestResponse = message.getMessageInfo();
        Message msg = new Message(requestResponse);
        for (AutoLoginItem item : table.getItemList()) {
            if (item.isEnabled() && item.getDomain().equals(msg.getDomain())) {
                Session session = item.getSession();
                if (!session.isValid(msg)) {
                    session.updateRequest(msg);
                    Message.refreshMessage(msg);
                    if (!session.isValid(msg)) {
                        session.login();
                        session.updateRequest(msg);
                        Message.refreshMessage(msg);
                        if (session.isValid(msg)) {
                            session.addSetCookieHeader(msg);
                            requestResponse.setResponse(msg.getResponse());
                        }
                    } else {
                        session.addSetCookieHeader(msg);
                        requestResponse.setResponse(msg.getResponse());
                    }
                }
                return;
            }
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        // TODO Auto-generated method stub
        try {
            if (invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER
                    && invocation.getSelectedMessages().length == 1
                    && invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
                JMenu menu = new JMenu(AutoLogin.name);
                JMenu updateRequestMenu = new JMenu(Util.l("update current request"));
                JMenu generateTokenReplaceMenu = new JMenu(
                        Util.l("generating a token replace rule by selection text"));
                List<JMenuItem> result = new Vector<>();
                IHttpRequestResponse requestResponse = invocation.getSelectedMessages()[0];
                Message msg = new Message(requestResponse);

                menu.add(updateRequestMenu);
                menu.add(generateTokenReplaceMenu);
                result.add(menu);
                updateRequestMenu.setEnabled(false);
                generateTokenReplaceMenu.setEnabled(false);
                menu.setEnabled(false);
                menu.setText(AutoLogin.name + Util.l("(need create login process)"));
                for (AutoLoginItem item : table.getItemList()) {
                    if (!item.getDomain().equals(msg.getDomain())) {
                        continue;
                    }
                    updateRequestMenu.setEnabled(true);
                    menu.setEnabled(true);
                    menu.setText(AutoLogin.name);
                    JMenuItem tmpMenu1 = new JMenuItem(item.getName());
                    JMenuItem tmpMenu2 = new JMenuItem(item.getName());
                    tmpMenu2.setEnabled(false);
                    updateRequestMenu.add(tmpMenu1);
                    generateTokenReplaceMenu.add(tmpMenu2);

                    if (menu.isEnabled()) {
                        updateRequestMenu.addActionListener(new ActionListener() {

                            @Override
                            public void actionPerformed(ActionEvent e) {
                                // TODO Auto-generated method stub
                                showReLoginDialog(requestResponse, item);
                            }

                        });
                        if (invocation.getSelectionBounds() != null) {
                            generateTokenReplaceMenu.setEnabled(true);
                            tmpMenu2.setEnabled(true);
                            Session session = item.getSession();
                            int[] bounds = invocation.getSelectionBounds();
                            Pattern pattern = Util.getPatternFromSelectedBounds(
                                    new String(requestResponse.getRequest()), bounds[0], bounds[1]);
                            if (pattern == null) {
                                tmpMenu2.setEnabled(false);
                            } else {
                                tmpMenu2.addActionListener(new ActionListener() {

                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        // TODO Auto-generated method stub
                                        showAddTokenReplaceDialog(session, pattern);
                                    }

                                });
                            }
                        }
                    }
                }

                return result;
            }
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 显示添加token替换规则的对话框，用于编辑
     * 
     * @param session 当前token替换规则对应的session
     * @param pattern 当前获得的替换规则
     */
    private void showAddTokenReplaceDialog(Session session, Pattern pattern) {
        JDialog dialog = new JDialog();
        JPanel panel = new JPanel();
        JTextArea patternTextArea = new JTextArea();
        JTextArea tipsTextArea = new JTextArea();
        JComboBox<String> tokenComboBox = new JComboBox<>();
        JButton addButton = new JButton(Util.l("ok"));
        JCheckBox useUrlEncodeBox = new JCheckBox(Util.l("replace result use url encoding"));

        for (Iterator<Message> iterator = session.getLoginMessages().iterator(); iterator.hasNext();) {
            for (Entry<Token, Pattern> entry : iterator.next().getTokenSearchModel().entrySet()) {
                tokenComboBox.addItem(entry.getKey().getTokenName());
            }
        }
        if (tokenComboBox.getItemCount() == 0) {
            JOptionPane.showMessageDialog(null, Util.l("token is null tips,you need to set token first!"));
            return;
        }

        patternTextArea.setText(pattern.pattern());
        tipsTextArea.setText("from selection");
        useUrlEncodeBox.setSelected(true);

        addButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent ee) {
                // TODO Auto-generated method stub
                try {
                    String pattern = Util.viewString(patternTextArea.getText());
                    Token token = session.getToken((String) tokenComboBox.getSelectedItem());
                    session.getTokenReplaceModel().append(token, Pattern.compile(pattern), tipsTextArea.getText(),
                            useUrlEncodeBox.isSelected());
                    dialog.dispose();
                } catch (PatternSyntaxException excep) {
                    // TODO: handle exception
                    JOptionPane.showMessageDialog(dialog, Util.l("regexp syntax error!"));
                }
            }

        });

        tokenComboBox.setBorder(BorderFactory.createTitledBorder(Util.l("token name")));
        patternTextArea.setBorder(BorderFactory.createTitledBorder(Util.l("token update regexp")));
        tipsTextArea.setBorder(BorderFactory.createTitledBorder(Util.l("describe")));
        patternTextArea.setToolTipText(Util.l("it is used to search token in request for updating."));
        panel.setLayout(new GridLayout(4, 1));
        JPanel tempPanel = new JPanel(new GridLayout(1, 2));
        tempPanel.add(tokenComboBox);
        tempPanel.add(useUrlEncodeBox);
        panel.add(tempPanel);
        panel.add(patternTextArea);
        panel.add(tipsTextArea);
        panel.add(addButton);
        dialog.setContentPane(panel);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setSize(new Dimension(400, 300));
        dialog.setTitle(Util.l("add token update rule"));
        Util.setToCenter(dialog);
        dialog.setModal(true);

        dialog.setVisible(true);
    }

    /**
     * 生成更新请求的对话框，用于显示更新进度
     * 
     * @param requestResponse 待更新的请求
     */
    private void showReLoginDialog(IHttpRequestResponse requestResponse, AutoLoginItem item) {
        JDialog dialog = new JDialog();
        JPanel panel = new JPanel(new GridLayout(1, 1));
        JProgressBar progressBar = new JProgressBar();
        progressBar.setStringPainted(false);
        JLabel msgLabel = new JLabel(Util.l("no login is built"));

        Message msg = new Message(requestResponse);
        Session session = item.getSession();
        if (item.getDomain().equals(msg.getDomain())) {
            progressBar.setStringPainted(true);
            progressBar.setMinimum(1);
            progressBar.setMaximum(session.getLoginMessages().size() + 2);
            panel.add(progressBar);
            // 更新来自repeater的请求
            TimerTask task = new TimerTask() {

                @Override
                public void run() {
                    // TODO Auto-generated method stub
                    int i = 1;
                    // 1.重放该请求，若登录状态失效则更新请求的cookie和token信息
                    Message.refreshMessage(msg);
                    progressBar.setValue(i++);
                    if (!session.isValid(msg)) {
                        session.updateRequest(msg);
                        Message.refreshMessage(msg);
                        progressBar.setValue(i++);
                        // 2.若登录状态还是失效，则重新登录刷新当前域的session信息
                        if (!session.isValid(msg)) {
                            LoginProcessor loginProcessor = session.loginProcessor();

                            while (loginProcessor.hasNext()) {
                                loginProcessor.step();

                                progressBar.setValue(i++);
                            }

                            session.updateRequest(msg);
                        }
                    }
                    progressBar.setValue(progressBar.getMaximum());
                    requestResponse.setRequest(msg.getRequest());

                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    dialog.dispose();
                }

            };
            dialog.addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    // TODO Auto-generated method stub
                    task.cancel();
                }
            });
            new Timer().schedule(task, 200);
        }

        if (!progressBar.isStringPainted()) {
            // 没有同域的登录过程
            panel.add(msgLabel);
        }

        dialog.setContentPane(panel);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setSize(new Dimension(400, 80));
        dialog.setTitle(Util.l("update request progress"));
        Util.setToCenter(dialog);
        dialog.setModal(true);
        dialog.setVisible(true);
    }

}