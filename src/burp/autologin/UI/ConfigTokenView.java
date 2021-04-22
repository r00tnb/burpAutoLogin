package burp.autologin.UI;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.GridLayout;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.MouseInputAdapter;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.Caret;
import javax.swing.text.Highlighter;
import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;
import javax.swing.text.Highlighter.Highlight;

import burp.BurpExtender;
import burp.IBurpExtender;
import burp.ITextEditor;
import burp.Util.TempEntry;
import burp.Util.Util;
import burp.autologin.UI.components.HTTPEditor;
import burp.autologin.UI.components.MyTable;
import burp.autologin.core.*;
import burp.autologin.core.Session.Token;
import javafx.scene.control.TableSelectionModel;

public class ConfigTokenView extends JDialog implements MouseListener {
    private AutoLoginItem item;
    JSplitPane panel;
    JPanel rightPanel;
    MyTable table;
    HTTPEditor editor;
    MyTable searchTable;
    MyTable allSearchTable;
    JTextArea nameField;
    JTextArea patternField;

    public ConfigTokenView(AutoLoginItem item) {
        setTitle(Util.l("configurate token"));
        setSize(new Dimension(1000, 600));
        Util.setToCenter(this);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        setModal(true);

        this.item = item;
        this.panel = new JSplitPane();
        this.rightPanel = new JPanel(new GridLayout(2, 1));
        this.editor = new HTTPEditor();
        this.searchTable = new MyTable();
        this.allSearchTable = new MyTable();
        this.table = new MyTable();
        table.setHeader("#", "Domain", "Method", "Url", "MIME Type", "Status");
        table.setHeaderWidth(10, 100, 30, 200, 40, 60);
        int i = 0;
        for (Iterator<Message> iterator = item.getSession().getLoginMessages().iterator(); iterator.hasNext(); i++) {
            Message msg = iterator.next();
            table.addRow(i, msg, msg.getMethod(), msg.getUrlPath(), msg.getMIMEType(), msg.getStatusInfo());
        }
        table.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.addMouseListener(this);
        if (table.getRowCount() > 0)
            setSelectedRow(0);

        // 添加文本选择事件处理
        editor.getCaret().addChangeListener(new ChangeListener() {

            @Override
            public void stateChanged(ChangeEvent e) {
                // TODO Auto-generated method stub
                TempEntry<String, Pattern> entry = editor.getSelectedTextPattern();
                if(entry.isEmpty()) return;
                nameField.setText(entry.getKey());
                patternField.setText(entry.getValue().pattern());
            }
            
        });

        setRightPanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(new JScrollPane(table));
        splitPane.setBottomComponent(new JScrollPane(editor));
        splitPane.setDividerLocation(200);
        panel.setLeftComponent(splitPane);
        panel.setRightComponent(rightPanel);
        panel.setDividerLocation(500);
        setContentPane(panel);
    }

    public void setRightPanel() {
        JPanel topPanel = new JPanel(new GridLayout(1, 2));
        JPanel tempPanel1 = new JPanel(new GridLayout(3, 1));
        this.nameField = new JTextArea();
        this.patternField = new JTextArea();
        nameField.setBorder(BorderFactory.createTitledBorder(Util.l("name")));
        patternField.setBorder(BorderFactory.createTitledBorder(Util.l("regexp")));
        tempPanel1.add(nameField);
        tempPanel1.add(patternField);

        JPanel tempPanel1_1 = new JPanel();
        JButton addBtn = new JButton(Util.l("add"));
        JButton removeBtn = new JButton(Util.l("delete seleted items"));
        tempPanel1_1.add(addBtn);
        tempPanel1_1.add(removeBtn);
        tempPanel1.add(tempPanel1_1);
        addBtn.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                Message msg = getSelectedMessage();
                if(msg == null) return;

                String name = nameField.getText();
                String value = patternField.getText();
                Pattern pattern;
                if(name == null || value == null || name.equals("") || value.equals("")){
                    JOptionPane.showMessageDialog(ConfigTokenView.this, Util.l("name or regexp is null!"));
                    return;
                }

                try {
                    pattern = Pattern.compile(value);
                } catch (PatternSyntaxException patternExcep) {
                    //TODO: handle exception
                    JOptionPane.showMessageDialog(ConfigTokenView.this, Util.l("regexp syntax error!"));
                    return;
                }

                Session session = item.getSession();
                if(session.hasToken(name)){
                    JOptionPane.showMessageDialog(ConfigTokenView.this, Util.l("token is existing!"));
                    return;
                }
                searchTable.addRow(name, value);
                msg.getTokenSearchModel().put(session.getToken(name), pattern);

                int pos = editor.getCaretPosition();
                editor.highlightKeyword();
                editor.setCaretPosition(pos);
                allSearchTable.addRow(name, value);
            }
            
        });
        removeBtn.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if(searchTable.getSelectedRows().length == 0) return;

                int[] rows = searchTable.getSelectedRows();
                for(int i=rows.length-1;i>=0;i--){
                    String tokenName = (String)searchTable.getValueAt(rows[i], 0);
                    allSearchTable.removeRowByColumn(0, tokenName);
                    searchTable.removeRow(rows[i]);
                    getSelectedMessage().getTokenSearchModel().remove(tokenName);
                }
                editor.highlightKeyword();
            }
            
        });

        Message msg = getSelectedMessage();
        editor.setMessage(msg);
        editor.highlightKeyword();
        
        searchTable.setHeader(Util.l("token name"), Util.l("regexp for search"));
        allSearchTable.setHeader(Util.l("token name"), Util.l("regexp for search"));
        allSearchTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        allSearchTable.addMouseListener(new MouseAdapter(){
            @Override
            public void mouseClicked(MouseEvent e) {
                // TODO Auto-generated method stub
                if(e.getButton() == MouseEvent.BUTTON1){
                    // 点击后定位到token位置
                    String tokenName = (String)allSearchTable.getValueAt(allSearchTable.getSelectedRow(), 0);
                    for(int i=0;i<table.getRowCount();i++){
                        Message temp = (Message)table.getValueAt(i, 1);
                        if(temp.getTokenSearchModel().isExist(tokenName)){
                            setSelectedRow(i);
                            searchTable.selectRowsByColumn(0, tokenName);
                            // editor中跳转到匹配到的token值
                            Integer v = temp.getTokenSearchModel().getMatchedTokenIndexs(tokenName).getValue();
                            if(v != null)
                                editor.setCaretPosition(v);
                            else{
                                JOptionPane.showMessageDialog(null, Util.l("the token is not found!"));
                            }
                        }
                    }
                }
            }
        });
        for(Iterator<Message> iterator=item.getSession().getLoginMessages().iterator();iterator.hasNext();){
            Message temp = iterator.next();
            TokenSearchModel searchModel = temp.getTokenSearchModel();
            for(Entry<Token, Pattern> search:searchModel.entrySet()){
                allSearchTable.addRow(search.getKey().getTokenName(), search.getValue().pattern());
                if(msg != null && temp == msg){
                    searchTable.addRow(search.getKey().getTokenName(), search.getValue().pattern());
                }
            }
        }

        topPanel.add(tempPanel1);
        topPanel.add(new JScrollPane(searchTable));
        topPanel.setBorder(BorderFactory.createTitledBorder(Util.l("configurate token")));
        rightPanel.add(topPanel);
        JScrollPane downPanel = new JScrollPane(allSearchTable);
        downPanel.setBorder(BorderFactory.createTitledBorder(Util.l("all search token")));
        rightPanel.add(downPanel);
    }

    public Message getSelectedMessage(){
        if(table.getRowCount() > 0)
            return (Message) table.getValueAt(table.getSelectedRow(), 1);
        return null;
    }

    public void setSelectedRow(int row) {
        table.setRowSelectionInterval(row, row);
        Message message = (Message) table.getValueAt(row, 1);
        editor.setMessage(message);
        editor.highlightKeyword();

        searchTable.removeRowAll();
        for(Iterator<Message> iterator=item.getSession().getLoginMessages().iterator();iterator.hasNext();){
            Message msg = iterator.next();
            TokenSearchModel searchModel = msg.getTokenSearchModel();
            if(msg == message){
                for(Entry<Token, Pattern> search:searchModel.entrySet()){
                    searchTable.addRow(search.getKey().getTokenName(), search.getValue().pattern());
                }
            }
        }
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        // TODO Auto-generated method stub
        if(e.getButton() == MouseEvent.BUTTON1){
            setSelectedRow(table.getSelectedRow());
        }
    }

    @Override
    public void mousePressed(MouseEvent e) {
        // TODO Auto-generated method stub

    }

    @Override
    public void mouseReleased(MouseEvent e) {
        // TODO Auto-generated method stub

    }

    @Override
    public void mouseEntered(MouseEvent e) {
        // TODO Auto-generated method stub

    }

    @Override
    public void mouseExited(MouseEvent e) {
        // TODO Auto-generated method stub

    }

}