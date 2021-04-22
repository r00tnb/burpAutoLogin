package burp.autologin.UI;

import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.GridBagConstraints;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import java.util.Iterator;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.ITextEditor;
import burp.Util.ProxyHandler;
import burp.Util.ProxyListener;
import burp.Util.Util;
import burp.autologin.UI.components.MyTable;
import burp.autologin.UI.components.SessionValidatorView;
import burp.autologin.UI.components.TokenReplacePanel;
import burp.autologin.core.*;
import burp.autologin.core.Session.LoginProcessor;
import burp.autologin.core.Session.Token;
import javafx.application.Application;

/**
 * Show settting items of AutoLoginItem
 */
public class SettingPanel extends JPanel {

    private AutoLoginItem item;
    private MessageTable messageTable;
    private GridBagConstraints constraint;
    private JPanel settingPanel;
    private TokenReplacePanel tokenReplacePanel;
    private MyTable tokenTable;

    public SettingPanel(AutoLoginItem item) {
        this.constraint = new GridBagConstraints();
        this.settingPanel = new JPanel();
        this.messageTable = new MessageTable();
        this.item = item;
        this.tokenReplacePanel = new TokenReplacePanel(item);
        this.tokenTable = new MyTable();
        this.messageTable.setMessageQueue(item.getSession().getLoginMessages());
        this.tokenReplacePanel.setAutoLoginItem(item);

        settingPanel.setLayout(new BoxLayout(settingPanel, BoxLayout.Y_AXIS));
        setLayout(new GridBagLayout());
        constraint.fill = GridBagConstraints.BOTH;
        setSettingPanel();

        add(messageTable, 0, 1, 2, 0, 0.9, 1);
        add(settingPanel, 2, 1, 0, 0, 0.1, 0);
    }

    public void setSettingPanel() {

        JButton recordLoginButton = new JButton(Util.l("edit and record login sequence"));
        JButton configMessageButton = new JButton(Util.l("configurate token"));
        JButton refreshBuntton = new JButton(Util.l("refresh session"));
        recordLoginButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                RecordLoginView loginView = new RecordLoginView(item);
                loginView.setVisible(true);
                messageTable.setMessageQueue(item.getSession().getLoginMessages());
                item.getSession().updateTokenReplaceModel();
                updateTokenTable();
                tokenReplacePanel.updateTable();
            }
            
        });
        configMessageButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if(item.getSession().getLoginMessages() == null || item.getSession().getLoginMessages().size()<1){
                    JOptionPane.showMessageDialog(null, Util.l("please record login sequence first"));
                    return;
                }
                
                ConfigTokenView configTokenView = new ConfigTokenView(item);
                configTokenView.setVisible(true);
                updateTokenTable();
            }
            
        });
        refreshBuntton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if(item.getSession().getLoginMessages() == null || item.getSession().getLoginMessages().size()<1){
                    JOptionPane.showMessageDialog(null, Util.l("please record login sequence first"));
                    return;
                }
                
                showRefreshSessionDialog();
                updateTokenTable();
                messageTable.setMessageQueue(item.getSession().getLoginMessages());
            }
            
        });

        //init token table
        tokenTable.setHeader(Util.l("name"), Util.l("value"));
        tokenTable.setHeaderWidth(20, 250);
        updateTokenTable();

        settingPanel.add(recordLoginButton);
        settingPanel.add(configMessageButton);
        settingPanel.add(refreshBuntton);
        JScrollPane tempJScrollPane = new JScrollPane(tokenTable);
        tempJScrollPane.setBorder(BorderFactory.createTitledBorder(Util.l("current token info")));
        tempJScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
        tokenReplacePanel.setBorder(BorderFactory.createTitledBorder(Util.l("token update settings")));
        tokenReplacePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        settingPanel.add(tempJScrollPane);
        settingPanel.add(tokenReplacePanel);

        JPanel sessionValidatorPanel = new SessionValidatorView(item);
        sessionValidatorPanel.setBorder(BorderFactory.createTitledBorder(Util.l("session invalid setttings")));
        sessionValidatorPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        settingPanel.add(sessionValidatorPanel);
    }


    public void updateTokenTable(){
        tokenTable.removeRowAll();
        for(Iterator<Token> iterator=item.getSession().getAllToken().iterator();iterator.hasNext();){
            Token token = iterator.next();
            tokenTable.addRow(token.getTokenName(), token.getTokenValue());
        }
    }

    private void add(Component comp, int x, int y, int w, int h, double weightx, double weighty){
        constraint.gridx = x;
        constraint.gridy = y;
        constraint.gridwidth  = w;
        constraint.gridheight = h;
        constraint.weightx = weightx;
        constraint.weighty = weighty;
        add(comp, constraint);
    }

    /**
     * 展示刷新session的进度条，并更新当前session信息
     */
    private void showRefreshSessionDialog(){
        JDialog dialog = new JDialog();
        JPanel panel = new JPanel(new GridLayout(1, 1));
        JProgressBar progressBar = new JProgressBar();
        Session session = item.getSession();
        
        progressBar.setStringPainted(true);
        progressBar.setMinimum(1);
        progressBar.setMaximum(session.getLoginMessages().size());
        panel.add(progressBar);
        // 刷新session
        session.clear();
        TimerTask task = new TimerTask() {

            @Override
            public void run() {
                // TODO Auto-generated method stub
                int i = 1;
                LoginProcessor loginProcessor = session.loginProcessor();          
                while (loginProcessor.hasNext()) {
                    loginProcessor.step();

                    progressBar.setValue(i++);
                }
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                dialog.dispose();
            }
            
        };
        dialog.addWindowListener(new WindowAdapter(){
            @Override
            public void windowClosing(WindowEvent e) {
                // TODO Auto-generated method stub
                task.cancel();
            }
        });
        new Timer().schedule(task, 200);

        dialog.setContentPane(panel);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setSize(new Dimension(400, 80));
        dialog.setTitle(Util.l("refresh session progress"));
        Util.setToCenter(dialog);
        dialog.setModal(true);
        dialog.setVisible(true);
    }

}