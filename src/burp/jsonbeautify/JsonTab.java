package burp.jsonbeautify;

import jsoncomp.JsonModel;
import jsoncomp.JsonNode;
import jsoncomp.JsonTree;
import jsoncomp.json.JSONParser;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JViewport;
import javax.swing.LookAndFeel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.tree.TreePath;

import burp.BurpExtender;
import burp.IBurpExtender;
import burp.IMessageEditorTab;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class JsonTab extends JScrollPane implements IMessageEditorTab, MouseListener {

    JsonTree tree;
    LineNumberHeaderView lineView;
    JTextArea textArea;
    JLabel loadingLabel;

    public JsonTab() {
        this.tree = new JsonTree();
        this.lineView = new LineNumberHeaderView();
        this.textArea = new JTextArea();
        this.loadingLabel = new JLabel("正在加载中。。。(Loading...)");

        setViewportView(loadingLabel);
        setRowHeaderView(lineView);
        // try {
        //     LookAndFeel old = UIManager.getLookAndFeel();
        //     UIManager.setLookAndFeel("javax.swing.plaf.metal.MetalLookAndFeel");
        //     SwingUtilities.updateComponentTreeUI(tree);
        //     UIManager.setLookAndFeel(old);
        // } catch (ClassNotFoundException | InstantiationException | IllegalAccessException
        //         | UnsupportedLookAndFeelException e) {
        //     // TODO Auto-generated catch block
        //     e.printStackTrace(BurpExtender.stderr);
        // }
        

        tree.addMouseListener(this);
        textArea.addMouseListener(this);
    }

    @Override
    public void setViewportView(Component view) {
        // TODO Auto-generated method stub
        super.setViewportView(view);
        if(tree == view){
            lineView.setLineHeight(tree.getRowHeight());
        }else if(view == textArea){
            lineView.setLineHeight(textArea.getFontMetrics(textArea.getFont()).getHeight());
        }
    }

    @Override
    public String getTabCaption() {
        // TODO Auto-generated method stub
        return "JsonBeautiful";
    }

    @Override
    public Component getUiComponent() {
        // TODO Auto-generated method stub
        return this;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        // TODO Auto-generated method stub
        if (content.length == 0 || getBodyJson(content, isRequest) == null)
            return false;
        if (!isRequest) {
            tree.setEditable(true);
        } else {
            tree.setEditable(true);
        }

        return true;
    }

    public String getBodyJson(byte[] content, boolean isRequest) {
        String jsonString;
        if (isRequest) {
            IRequestInfo info = BurpExtender.helpers.analyzeRequest(content);
            String encoding = getContentType(info.getHeaders());
            try {
                jsonString = new String(content, info.getBodyOffset(), content.length - info.getBodyOffset(), encoding == null?"UTF-8":encoding);
                new JSONParser().fromJSON(jsonString);
            } catch (Exception e) {
                // TODO Auto-generated catch bloc
                jsonString = null;
            }
        }else{
            IResponseInfo info = BurpExtender.helpers.analyzeResponse(content);
            String encoding = getContentType(info.getHeaders());
            try {
                jsonString = new String(content, info.getBodyOffset(), content.length - info.getBodyOffset(), encoding == null?"UTF-8":encoding);
                new JSONParser().fromJSON(jsonString);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                jsonString = null;
            }
        }

        return jsonString;
    }

    public String getContentType(List<String> headers){
        for(String s:headers){
            if(s.startsWith("Content-Type")){
                Matcher matcher = Pattern.compile("charset=([\\w\\-]+)[\\s,;]*").matcher(s);
                if(matcher.find()){
                    return matcher.group(1);
                }
            }
        }
        return null;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        // TODO Auto-generated method stub
        setViewportView(loadingLabel);
        SwingUtilities.invokeLater(new Runnable(){

            @Override
            public void run() {
                // TODO Auto-generated method stub
                tree.setModel(new JsonModel(getBodyJson(content, isRequest)));
                tree.expandAll();
                setViewportView(tree);
            }
            
        });
    }

    @Override
    public byte[] getMessage() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isModified() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        // TODO Auto-generated method stub
        if(e.isMetaDown()){
            JPopupMenu menu = new JPopupMenu();
            JMenuItem showSourceMenu = new JMenuItem();
            if(e.getSource() == tree){
                showSourceMenu.setText("show json source");
            }else{
                showSourceMenu.setText("show json tree");
            }
            showSourceMenu.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    if(e.getSource() == tree){
                        textArea.setText(tree.toString());
                        JsonTab.this.setViewportView(textArea);
                    }else{
                        setViewportView(loadingLabel);
                        SwingUtilities.invokeLater(new Runnable(){

                            @Override
                            public void run() {
                                // TODO Auto-generated method stub
                                tree.setModel(new JsonModel(textArea.getText()));
                                tree.expandAll();
                                setViewportView(tree);
                            }
                            
                        });
                    }
                    
                }
                            
            });
            menu.add(showSourceMenu);

            if(e.getSource() == tree){
                JMenuItem expandMenu = new JMenuItem("expand all");
                JMenuItem collapseMenu = new JMenuItem("collapse all");
                ActionListener aListener = new ActionListener(){

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // TODO Auto-generated method stub
                        if(e.getActionCommand().equals("expand all")){
                            tree.expandAll();
                        }else if(e.getActionCommand().equals("collapse all")){
                            tree.collapseAll();
                            tree.expandPath(new TreePath(((JsonNode)tree.getModel().getRoot()).getPath()));
                        }
                    }
                    
                };
                expandMenu.addActionListener(aListener);
                collapseMenu.addActionListener(aListener);
                menu.add(expandMenu);
                menu.add(collapseMenu);
            }
            menu.show(e.getComponent(), e.getX(), e.getY());
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