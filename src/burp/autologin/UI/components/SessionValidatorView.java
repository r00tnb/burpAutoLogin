package burp.autologin.UI.components;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Component;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListModel;
import javax.swing.ListSelectionModel;

import burp.Util.TempEntry;
import burp.Util.Util;
import burp.autologin.core.AutoLoginItem;
import burp.autologin.core.SessionValidator;
import burp.autologin.core.SessionValidator.SessionValidatorType;
import burp.autologin.core.SessionValidator.ValidatorItem;

public class SessionValidatorView extends JPanel {
    private AutoLoginItem item;

    private MyTable table;

    public SessionValidatorView(AutoLoginItem item) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        this.item = item;
        this.table = new MyTable();

        table.setHeader("#", "tips", "obj");
        table.hiddenColumn(2);
        table.hiddenColumn(0);
        //table.setHeaderWidth(10, 300);
        int i = 0;
        for (SessionValidator validator : item.getSession().getSessionValidatorList()) {
            table.addRow(i, validator.toString(), validator);
            i++;
        }

        JButton addBtn = new JButton(Util.l("add session invalid rule"));
        JButton removeBtn = new JButton(Util.l("delete seleted items"));
        JButton editBtn = new JButton(Util.l("edit seleted item"));
        JPanel tempPanel = new JPanel();
        tempPanel.add(addBtn);
        tempPanel.add(removeBtn);
        tempPanel.add(editBtn);
        tempPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        addBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                JDialog dialog = addOrEditDialog(false);
                dialog.setVisible(true);

            }
            
        });
        editBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if(getSeletedValidator() == null) return;
                JDialog dialog = addOrEditDialog(true);
                dialog.setVisible(true);
            }
            
        });
        removeBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                int[] rows = table.getSelectedRows();
                for(int i=rows.length-1;i>=0;i--){
                    SessionValidator validator = (SessionValidator)table.getValueAt(rows[i], 2);
                    table.removeRow(rows[i]);
                    item.getSession().getSessionValidatorList().remove(validator);
                }
            }
            
        });

        JScrollPane tempScrollPane = new JScrollPane(table);
        tempScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(tempPanel);
        add(tempScrollPane);
    }

    private JDialog addOrEditDialog(boolean edit){
        JDialog dialog = new JDialog();
        JPanel panel = new JPanel();
        panel.setLayout(null);
        panel.setPreferredSize(new Dimension(400, 400));
        int leftWidth = 150;
        int rightWidth = 400;
        int height = 30;
        int x = 20;
        int y = 20;

        JComboBox<SessionValidatorType> typeComboBox = new JComboBox<>(SessionValidatorType.values());
        JLabel typeLabel = new JLabel(Util.l("type")+":");
        typeLabel.setBounds(x, y, leftWidth, height);
        typeComboBox.setBounds(x+leftWidth, y, rightWidth, height);
        panel.add(typeLabel);
        panel.add(typeComboBox);

        JTextArea textArea = new JTextArea();
        textArea.setLineWrap(true);
        JLabel contentLabel = new JLabel(Util.l("expression")+":");
        JScrollPane textScrollPane = new JScrollPane(textArea);
        JButton addBtn = new JButton(Util.l("add"));
        y = y+height+10;
        contentLabel.setBounds(x, y, leftWidth, height);
        textScrollPane.setBounds(x+leftWidth, y, rightWidth-150, 100);
        addBtn.setBounds(x+leftWidth+rightWidth-150, y, 150, height);
        panel.add(contentLabel);
        panel.add(textScrollPane);
        panel.add(addBtn);

        JList<ValidatorItem> validatorListView = new JList<>(new DefaultListModel<>());
        JScrollPane listScrollPane = new JScrollPane(validatorListView);
        JLabel listLabel = new JLabel(Util.l("session invalid rule list")+":");
        JButton removeBtn = new JButton(Util.l("delete seleted items"));
        JButton editBtn = new JButton(Util.l("edit seleted item"));
        validatorListView.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        y = y+100+10;
        listLabel.setBounds(x, y, leftWidth, height);
        listScrollPane.setBounds(x+leftWidth, y, rightWidth-150, 100);
        removeBtn.setBounds(x+leftWidth+rightWidth-150, y, 150, height);
        editBtn.setBounds(x+leftWidth+rightWidth-150, y+height, 150, height);
        panel.add(listLabel);
        panel.add(listScrollPane);
        panel.add(removeBtn);
        panel.add(editBtn);

        DefaultListModel<ValidatorItem> validatorListModel = (DefaultListModel<ValidatorItem>)validatorListView.getModel();
        SessionValidator validator = edit?getSeletedValidator():new SessionValidator();
        if(edit){
            for(ValidatorItem validatorItem:validator){
                validatorListModel.addElement(validatorItem);
            }
        }

        addBtn.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                String text = textArea.getText();
                SessionValidatorType type = (SessionValidatorType)typeComboBox.getSelectedItem();
                if(type.getName().contains("(regexp)")){
                    text = Util.viewString(text);
                    try {
                        Pattern.compile(text);
                    } catch (PatternSyntaxException ee) {
                        JOptionPane.showMessageDialog(dialog, Util.l("regexp syntax error!"));
                        return;
                    }
                }
                ValidatorItem element = validator.add(text, (SessionValidatorType)typeComboBox.getSelectedItem());
                textArea.setText("");
                validatorListModel.addElement(element);
            }
            
        });
        removeBtn.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                ValidatorItem validatorItem = validatorListView.getSelectedValue();
                if(validatorItem != null){
                    validator.remove(validatorItem);
                    validatorListModel.remove(validatorListView.getSelectedIndex());
                }
            }
            
        });
        editBtn.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                ValidatorItem validatorItem = validatorListView.getSelectedValue();
                if(validatorItem != null){
                    validator.remove(validatorItem);
                    validatorListModel.remove(validatorListView.getSelectedIndex());

                    textArea.setText(validatorItem.getPattern());
                    typeComboBox.setSelectedItem(validatorItem.getType());
                }
            }
            
        });

        dialog.addWindowListener(new WindowAdapter(){
            @Override
            public void windowClosing(WindowEvent e) {
                // TODO Auto-generated method stub
                if(!edit && validator.size() > 0){
                    item.getSession().getSessionValidatorList().add(validator);
                    table.addRow(table.getRowCount(), validator.toString(), validator);
                }else if(edit && table.getSelectedRows().length>0){
                    table.updateRow(table.getSelectedRow(), table.getSelectedRow(), validator.toString(), validator);
                }

            }
        });

        dialog.setContentPane(panel);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setSize(new Dimension(650, 350));
        dialog.setTitle(edit?Util.l("edit session invalid rule"):Util.l("add session invalid rule"));
        Util.setToCenter(dialog);
        dialog.setModal(true);
        return dialog;
    }

    public SessionValidator getSeletedValidator(){
        if(table.getSelectedRows().length == 0) return null;
        return (SessionValidator)table.getValueAt(table.getSelectedRow(), 2);
    }

}