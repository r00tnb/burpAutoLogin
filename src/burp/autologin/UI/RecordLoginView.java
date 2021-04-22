package burp.autologin.UI;

import java.awt.Dimension;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Color;
import java.awt.Component;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import burp.IInterceptedProxyMessage;
import burp.Util.ProxyHandler;
import burp.Util.ProxyListener;
import burp.Util.Util;
import burp.autologin.core.*;

/**
 * Popen a dialog for recoding login queue.
 */
public class RecordLoginView extends JDialog {

    JPanel panel;
    ProxyHandler handler;
    AutoLoginItem item;
    boolean onlyDomain;
    boolean filterStaticMsg;
    MessageTable messageTable;
    JPanel rightPanel;
    GridBagConstraints constraint;

    public RecordLoginView(AutoLoginItem item) {
        this.item = item;
        this.onlyDomain = true;
        this.filterStaticMsg = true;
        this.messageTable = new MessageTable();
        messageTable.setMessageQueue(item.getSession().getLoginMessages());
        messageTable.setEditable(true);

        setTitle(Util.l("edit and record login sequence"));
        setSize(new Dimension(900, 700));
        Util.setToCenter(this);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        setModal(true);
        this.handler = new ProxyHandler() {

            @Override
            public void handle(boolean messageIsRequest, IInterceptedProxyMessage message) {
                // TODO Auto-generated method stub
                if (!messageIsRequest) {
                    Message msg = new Message(message.getMessageInfo());
                    if(!onlyDomain || msg.getDomain().equals(item.getDomain())){
                        if(filterStaticMsg && msg.isStaticMessage()) return;

                        messageTable.addMessage(msg);
                        if(messageTable.getTable().getSelectedRowCount() == 0)
                            messageTable.setSelectedRow(0);
                    }
                    
                }
            }

        };
        this.rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        this.panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        this.constraint = new GridBagConstraints();
        constraint.fill = GridBagConstraints.BOTH;
        setRightPanel();

        add(messageTable, 0, 1, 2, 0, 0.9, 1);
        add(rightPanel, 2, 1, 0, 0, 0.1, 0);
        
        setContentPane(panel);
        
    }

    private void add(Component comp, int x, int y, int w, int h, double weightx, double weighty){
        constraint.gridx = x;
        constraint.gridy = y;
        constraint.gridwidth  = w;
        constraint.gridheight = h;
        constraint.weightx = weightx;
        constraint.weighty = weighty;
        panel.add(comp, constraint);
    }

    public void setRightPanel() {
        JButton deleteSelectedButton = new JButton(Util.l("delete seleted items"));
        JButton okButton = new JButton(Util.l("ok"));
        JCheckBox interceptButton = new JCheckBox(Util.l("recording login sequence from proxy"));
        JCheckBox allInterceptButton = new JCheckBox(Util.l("only record the requests of same domain"));
        JCheckBox filterStaticMsgButton = new JCheckBox(Util.l("filter static message"));
        filterStaticMsgButton.setToolTipText(Util.l("filter static message.Like .css, .js, .png .... and response body like image, script"));
        filterStaticMsgButton.setSelected(filterStaticMsg);
        JButton clearAllButton = new JButton(Util.l("clear"));
        allInterceptButton.setSelected(onlyDomain);

        interceptButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                JCheckBox checkBox = (JCheckBox)e.getSource();
                if(checkBox.isSelected()){
                    ProxyListener.getProxyListener().addHandler(handler);
                }else{
                    ProxyListener.getProxyListener().removeHandler(handler);
                }
            }
            
        });
        allInterceptButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                JCheckBox checkBox = (JCheckBox)e.getSource();
                if(checkBox.isSelected()){
                    onlyDomain = true;
                }else{
                    onlyDomain = false;
                }
            }

        });
        filterStaticMsgButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                JCheckBox checkBox = (JCheckBox)e.getSource();
                if(checkBox.isSelected()){
                    filterStaticMsg = true;
                }else{
                    filterStaticMsg = false;
                }
            }

        });
        deleteSelectedButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                messageTable.removeSelectedRows();
            }
            
        });
        okButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if(JOptionPane.showConfirmDialog(RecordLoginView.this, Util.l("it will cover old settings")) != 0) return;

                messageTable.saveCurrentMessage();
                item.getSession().setLoginMessages(messageTable.getMessageQueue());
                RecordLoginView.this.dispose();
            }
            
        });
        clearAllButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if(JOptionPane.showConfirmDialog(RecordLoginView.this, Util.l("are you sure clear?")) != 0) return;
                messageTable.clear();
            }
            
        });

        rightPanel.add(interceptButton);
        rightPanel.add(allInterceptButton);
        rightPanel.add(filterStaticMsgButton);
        rightPanel.add(deleteSelectedButton);
        rightPanel.add(clearAllButton);
        rightPanel.add(okButton);
    }

    @Override
    protected void processWindowEvent(WindowEvent e) {
        // TODO Auto-generated method stub
        if(e.getID() == WindowEvent.WINDOW_CLOSED){
            ProxyListener.getProxyListener().removeHandler(handler);
        }
        
        super.processWindowEvent(e);
    }

}