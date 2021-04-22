package burp.autologin.UI.components;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.GridLayout;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import burp.Util.TempEntry;
import burp.Util.Util;
import burp.autologin.core.AutoLoginItem;
import burp.autologin.core.Message;
import burp.autologin.core.Session;
import burp.autologin.core.TokenReplaceModel;
import burp.autologin.core.Session.Token;
import burp.autologin.core.TokenReplaceModel.TokenReplace;

public class TokenReplacePanel extends JPanel {
    private MyTable table;
    private AutoLoginItem item;
    private JButton addBtn;
    private JButton removeBtn;
    private JCheckBox defaultReplaceBtn;
    private JButton editBtn;

    public TokenReplacePanel(AutoLoginItem item) {
        this.table = new MyTable(){
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                // TODO Auto-generated method stub
                if(columnIndex == 4)
                    return Boolean.class;
                return super.getColumnClass(columnIndex);
            }
        };
        this.addBtn = new JButton(Util.l("add token update rule"));
        this.removeBtn = new JButton(Util.l("delete seleted items"));
        this.editBtn = new JButton(Util.l("edit seleted item"));
        this.defaultReplaceBtn = new JCheckBox(Util.l("update all token in request"));
        defaultReplaceBtn.setToolTipText(Util.l("it will update token in request's query parameters,POST parameters,header and cookie."));
        defaultReplaceBtn.setSelected(item.getSession().getTokenReplaceModel().isAllReplace());
        JPanel tempPanel = new JPanel();
        tempPanel.add(addBtn);
        tempPanel.add(removeBtn);
        tempPanel.add(editBtn);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        tempPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(defaultReplaceBtn);
        add(tempPanel);
        add(scrollPane);

        removeBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                removeSeletedRows();
            }

        });
        addBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                JDialog dialog = replaceTokenDialog(false);
                if(dialog != null)
                    dialog.setVisible(true);
            }

        });
        editBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if(table.getSelectedRow() < 0) return;
                JDialog dialog = replaceTokenDialog(true);
                if(dialog != null)
                    dialog.setVisible(true);
            }

        });

        defaultReplaceBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                item.getSession().getTokenReplaceModel().setAllReplace(defaultReplaceBtn.isSelected());
            }
        });

        setAutoLoginItem(item);
    }

    public void setAutoLoginItem(AutoLoginItem item) {
        if(item == null) return;
        this.item = item;

        table.setHeader("#", Util.l("token update regexp"), Util.l("token name"), Util.l("describe"), Util.l("use url encode"), "obj");
        table.hiddenColumn(5);
        table.setHeaderWidth(5, 60, 15, 60, 20);
        updateTable();
    }

    public void updateTable(){
        table.removeRowAll();
        TokenReplaceModel replaceModel = item.getSession().getTokenReplaceModel();
        for(int i=0;i<replaceModel.size();i++){
            TokenReplace tokenReplace = replaceModel.get(i);
            table.addRow(i, tokenReplace.getPattern().pattern(), tokenReplace.getToken().getTokenName(),
                tokenReplace.getTips(), tokenReplace.isUseUrlEncode(), tokenReplace);
        }
    }

    public void removeSeletedRows(){
        int[] rows = table.getSelectedRows();
        for(int i=rows.length-1;i>=0;i--){
            TokenReplace tokenReplace = getTokenReplaceByRow(rows[i]);
            item.getSession().getTokenReplaceModel().remove(tokenReplace);
            table.removeRow(rows[i]);
        }
    }

    /** 根据行号返回改行对应的TokenReplace对象 */
    public TokenReplace getTokenReplaceByRow(int row){
        return (TokenReplace)table.getValueAt(row, table.getColumnCount()-1);
    }

    public JDialog replaceTokenDialog(boolean edit){
        JDialog dialog = new JDialog();
        JPanel panel = new JPanel();
        JTextArea patternTextArea = new JTextArea();
        JTextArea tipsTextArea = new JTextArea();
        JComboBox<String> tokenComboBox = new JComboBox<>();
        JButton addButton = new JButton(Util.l("ok"));
        JCheckBox useUrlEncodeBox = new JCheckBox(Util.l("replace result use url encoding"));

        for (Iterator<Message> iterator = TokenReplacePanel.this.item.getSession().getLoginMessages().iterator(); iterator
                .hasNext();) {
            for (Entry<Token, Pattern> entry : iterator.next().getTokenSearchModel().entrySet()) {
                tokenComboBox.addItem(entry.getKey().getTokenName());
            }
        }
        if (tokenComboBox.getItemCount() == 0) {
            JOptionPane.showMessageDialog(null, Util.l("token is null tips,you need to set token first!"));
            return null;
        }
        if(edit){
            tokenComboBox.setSelectedItem(table.getValueAt(table.getSelectedRow(), 2));
            patternTextArea.setText((String)table.getValueAt(table.getSelectedRow(), 1));
            tipsTextArea.setText((String)table.getValueAt(table.getSelectedRow(), 3));
            useUrlEncodeBox.setSelected((Boolean)table.getValueAt(table.getSelectedRow(), 4));
        }

        addButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent ee) {
                // TODO Auto-generated method stub
                try {
                    String pattern = Util.viewString(patternTextArea.getText());
                    Token token = item.getSession().getToken((String) tokenComboBox.getSelectedItem());
                    if(edit){
                        TokenReplace tokenReplace = getTokenReplaceByRow(table.getSelectedRow());
                        tokenReplace.set(token,Pattern.compile(pattern),tipsTextArea.getText(), useUrlEncodeBox.isSelected());
                    }else{
                        item.getSession().getTokenReplaceModel().append(token,Pattern.compile(pattern),
                            tipsTextArea.getText(), useUrlEncodeBox.isSelected());
                    }
                    updateTable();
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
        dialog.setTitle(edit?Util.l("edit token update rule"):Util.l("add token update rule"));
        Util.setToCenter(dialog);
        dialog.setModal(true);

        return dialog;
    }
}