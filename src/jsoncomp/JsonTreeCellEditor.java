package jsoncomp;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.*;
import java.awt.FlowLayout;
import java.awt.FontMetrics;
import java.awt.GridLayout;
import java.util.EventObject;
import java.util.regex.Pattern;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.event.CellEditorListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeCellEditor;

class ChangeWidthListener implements DocumentListener{
    JTextArea component;

    public ChangeWidthListener(JTextArea component){
        this.component = component;
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        // TODO Auto-generated method stub
        Document doc = e.getDocument();
        try {
            String text = doc.getText(0, doc.getLength());
            int width = component.getFontMetrics(component.getFont()).stringWidth(text+"1");
            int height = (int)component.getPreferredSize().getHeight();
            component.setPreferredSize(new Dimension(width, height));
        } catch (BadLocationException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        // TODO Auto-generated method stub
        Document doc = e.getDocument();
        try {
            String text = doc.getText(0, doc.getLength());
            int width = component.getFontMetrics(component.getFont()).stringWidth(text+"1");
            int height = (int)component.getPreferredSize().getHeight();
            component.setPreferredSize(new Dimension(width, height));
            //component.repaint();
        } catch (BadLocationException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        // TODO Auto-generated method stub

    }
    
}

public class JsonTreeCellEditor implements TreeCellEditor {

    JTextArea keyField;
    JTextArea valueField;
    JsonNode node;
    boolean expanded;

    public JsonTreeCellEditor() {
        this.keyField = new JTextArea();
        this.valueField = new JTextArea();
        //valueField.setLineWrap(true);
        
    }

    @Override
    public Object getCellEditorValue() {
        // TODO Auto-generated method stub
        //System.out.println(keyField.getText());
        if(!node.isRoot()&&!node.getParent().valueIsList()){
            node.setKey(keyField.getText());
        }
        if(node.valueIsObject()||node.valueIsList()){
            return node;
        }
        
        String value = valueField.getText();
        Double doubleNum = 0.1;
        Long intNum = 0L;
        boolean isInt = true;
        boolean isDouble = true;
        try {
            intNum = Long.parseLong(value);
        } catch (NumberFormatException e) {
            //TODO: handle exception
            isInt = false;
            try {
                doubleNum = Double.parseDouble(value);
            } catch (NumberFormatException ee) {
                //TODO: handle exception
                isDouble = false;
            }
        }

        if(isInt){
            node.setValue(intNum);
        }else if(isDouble){
            node.setValue(doubleNum);
        }else if(value.startsWith("\"") && value.endsWith("\"")){
            node.setValue(value.substring(1, value.length()-1));
        }else if(value.equals("true")){
            node.setValue(true);
        }else if(value.equals("false")){
            node.setValue(false);
        }else if(value.toLowerCase().equals("null")){
            node.setValue(null);
        }else{
            node.setValue(value);
        }
        return node;
    }

    @Override
    public boolean isCellEditable(EventObject anEvent) {
        // TODO Auto-generated method stub
        if(anEvent instanceof MouseEvent){
            MouseEvent event = (MouseEvent)anEvent;
            if(event.getClickCount() == 2){
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean shouldSelectCell(EventObject anEvent) {
        // TODO Auto-generated method stub
        if(anEvent instanceof MouseEvent){
            return true;
        }
        return false;
    }

    @Override
    public boolean stopCellEditing() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void cancelCellEditing() {
        // TODO Auto-generated method stub

    }

    @Override
    public void addCellEditorListener(CellEditorListener l) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void removeCellEditorListener(CellEditorListener l) {
        // TODO Auto-generated method stub

    }

    @Override
    public Component getTreeCellEditorComponent(JTree tree, Object value, boolean isSelected, boolean expanded,
            boolean leaf, int row) {
        // TODO Auto-generated method stub
        if(!(value instanceof JsonNode)){
            return null;
        }
        JPanel panel = new JPanel();
        JLabel splitLabel = new JLabel(": ");
        JLabel keyLabel = new JLabel();
        JLabel valueLabel = new JLabel();
        node = (JsonNode)value;
        this.expanded = expanded;
        valueField.setText(null);
        keyField.setText(null);

        keyField.setText(node.getkey());
        keyLabel.setText(node.getkey());
        if(node.valueIsObject()){
            if(node.getChildCount() == 0)   
                valueLabel.setText("{}");
            else
                valueLabel.setText("{...}");
        }else if(node.valueIsList()){
            if(node.getChildCount() == 0)   
                valueLabel.setText("[]");
            else
                valueLabel.setText("[...]");
        }else{
            if(node.valueIsString()){
                valueLabel.setText("\""+node.getValue().toString()+"\"");
                valueField.setText("\""+node.getValue().toString()+"\"");
            }else{
                valueField.setText(node.valueIsNull()?"null":node.getValue().toString());
                valueLabel.setText(node.valueIsNull()?"null":node.getValue().toString());
            }
        }

        if(node.isRoot()){
            panel.add(keyLabel);
        }else if(node.getParent().valueIsList()){
            keyLabel.setText(node.getParent().getIndex(node)+"");
            panel.add(keyLabel);
        }else{
            JLabel leftQuoteLabel = new JLabel("\"");
            JLabel rightQuotLabel = new JLabel("\"");
            JPanel keyPanel = new JPanel();
            keyPanel.add(leftQuoteLabel);
            keyPanel.add(keyField);
            keyPanel.add(rightQuotLabel);

            ((FlowLayout)keyPanel.getLayout()).setHgap(0);
            panel.add(keyPanel);
        }

        panel.add(splitLabel);

        if(!node.isLeaf()){
            panel.add(valueLabel);
        }else{
            panel.add(valueField);
        }
        
        keyField.getDocument().addDocumentListener(new ChangeWidthListener(keyField));
        valueField.getDocument().addDocumentListener(new ChangeWidthListener(valueField));
        ((FlowLayout)panel.getLayout()).setAlignment(FlowLayout.LEFT);
        ((FlowLayout)panel.getLayout()).setVgap(0);
        //panel.setLayout(new GridLayout());
        panel.setPreferredSize(new Dimension((int)tree.getPreferredSize().getWidth(), (int)panel.getPreferredSize().getHeight()));
        
        return panel;
    }

    
}