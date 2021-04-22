package burp.autologin.UI;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Vector;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import burp.BurpExtender;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.autologin.UI.components.MyTable;
import burp.autologin.core.*;

public class MessageTable extends JSplitPane implements MouseListener {
    private List<Message> messageQueue;
    private JTabbedPane tabbedPane;
    private JScrollPane scrollPane;
    private MyTable table;
    private IMessageEditor requestEditor;
    private IMessageEditor responeEditor;
    private boolean edit;
    private Message currentMessage;

    public MessageTable(){
        this(null);
    }

    public MessageTable(List<Message> messageQueue) {
        super(JSplitPane.VERTICAL_SPLIT);
        this.table = new MyTable();
        this.tabbedPane = new JTabbedPane();
        this.scrollPane = new JScrollPane(table);
        this.messageQueue = new Vector<>();
        this.edit = false;

        IMessageEditorController controller = new IMessageEditorController(){

            @Override
            public IHttpService getHttpService() {
                // TODO Auto-generated method stub
                return currentMessage.getHttpService();
            }

            @Override
            public byte[] getRequest() {
                // TODO Auto-generated method stub
                return currentMessage.getRequest();
            }

            @Override
            public byte[] getResponse() {
                // TODO Auto-generated method stub
                return currentMessage.getResponse();
            }
            
        };
        this.requestEditor = BurpExtender.callbacks.createMessageEditor(controller, true);
        this.responeEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
        requestEditor.setMessage("".getBytes(), true);
        responeEditor.setMessage("".getBytes(), false);
        tabbedPane.addTab("Request", requestEditor.getComponent());
        tabbedPane.addTab("Response", responeEditor.getComponent());

        setMessageQueue(messageQueue);
        table.addMouseListener(this);
        if(table.getRowCount() > 0)
            setSelectedRow(0);
        setDividerLocation(200);

        setTopComponent(scrollPane);
        setBottomComponent(tabbedPane);
    }

    public void setEditable(boolean edit){
        this.edit = edit;
    }

    public MyTable getTable(){
        return table;
    }

    public void setMessageQueue(List<Message> msgQueue){
        clear();
        if(msgQueue != null){
            this.messageQueue = new LinkedList<>(msgQueue);
        }

        table.setHeader("#", "Domain", "Method", "Path", "MIME Type", "Status");
        table.setHeaderWidth(10, 100, 30, 200, 40, 60);
        int i = 0;
        for (Iterator<Message> iterator = messageQueue.iterator(); iterator.hasNext(); i++) {
            Message message = iterator.next();
            table.addRow(i, message, message.getMethod(), message.getUrlPath(), message.getMIMEType(), message.getStatusInfo());
        }
        if(table.getRowCount()>0)
            setSelectedRow(0);
    }

    /**
     * 清空表
     */
    public void clear(){
        for(int i=table.getRowCount()-1;i>=0;i--){
            table.removeRow(i);
        }
        messageQueue.clear();
        requestEditor.setMessage("".getBytes(), true);
        responeEditor.setMessage("".getBytes(), false);
    }

    public void addMessage(Message message) {
        table.addRow(table.getRowCount(), message, message.getMethod(), message.getUrlPath(), message.getMIMEType(), message.getStatusInfo());
        this.messageQueue.add(message);
    }
    public void removeSelectedRows(){
        int[] rows = table.getSelectedRows();
        for(int i=rows.length-1;i>=0;i--){
            messageQueue.remove((Message)table.getValueAt(rows[i], 1));
            table.removeRow(rows[i]);
        }
    }

    public void setSelectedRow(int row){
        if(edit){
            saveCurrentMessage();
        }

        table.setRowSelectionInterval(row, row);
        currentMessage = (Message)table.getValueAt(row, 1);

        requestEditor.setMessage(currentMessage.getRequest(), true);
        responeEditor.setMessage(currentMessage.getResponse(), false);
    }

    /**
     * 保存当前编辑器的请求内容
     */
    public void saveCurrentMessage(){
        if(requestEditor != null && currentMessage != null){
            currentMessage.setRequest(requestEditor.getMessage());
        }
    }

    public List<Message> getMessageQueue() {
        return messageQueue;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        // TODO Auto-generated method stub
        if(e.getButton() == e.BUTTON1){
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