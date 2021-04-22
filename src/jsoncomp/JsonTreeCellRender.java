package jsoncomp;

import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.UIManager;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeCellRenderer;

public class JsonTreeCellRender extends DefaultTreeCellRenderer {

    boolean coloring = true;

    public void setColoring(boolean coloring){
        this.coloring = coloring;
    }

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
            boolean leaf, int row, boolean hasFocus) {
        // TODO Auto-generated method stub
        Component defaultComponent = super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
        if(!(value instanceof JsonNode)){
            return defaultComponent;
        }
        JPanel panel = new JPanel();
        JPanel keyPanel = new JPanel();
        JPanel valuePanel = new JPanel();
        JLabel keyLabel = new JLabel();
        JLabel valueLabel = new JLabel();
        JLabel splitLabel = new JLabel(": ");
        JLabel leftQuote1 = new JLabel();
        JLabel rightQuote1 = new JLabel();
        JLabel leftQuote2 = new JLabel();
        JLabel rightQuote2 = new JLabel();
        JLabel lengthLabel = new JLabel();
        JsonNode node = (JsonNode)value;

        lengthLabel.setFont(new Font(getFont().getFontName(), Font.ITALIC, 10));
        if(!node.isLeaf())
            lengthLabel.setText("length="+node.getChildCount());

        if(coloring){
            leftQuote1.setForeground(Color.BLUE);
            leftQuote2.setForeground(Color.BLUE);
            rightQuote2.setForeground(Color.BLUE);
            rightQuote1.setForeground(Color.BLUE);
            lengthLabel.setForeground(Color.GRAY);

            if(node.isRoot()||node.getParent().valueIsList())
                keyLabel.setForeground(Color.PINK);
            else{
                keyLabel.setForeground(Color.BLUE);
            }

            if(node.valueIsObject()||node.valueIsList()){
                valueLabel.setForeground(Color.GREEN);
            }else if(node.valueIsString()){
                valueLabel.setForeground(new Color(220,20,60));
            }else if(node.valueIsNull()){
                valueLabel.setForeground(Color.PINK);
            }else if(node.valueIsBoolean()){
                valueLabel.setForeground(Color.BLUE);
            }else if(node.valueIsNumber()){
                valueLabel.setForeground(new Color(	230,165,0));
            }
        }

        if(node.valueIsObject()){
            if(node.getChildCount() == 0)   
                valueLabel.setText("{}");
            else if(!expanded)
                valueLabel.setText("{...}");
        }else if(node.valueIsList()){
            if(node.getChildCount() == 0)   
                valueLabel.setText("[]");
            else if(!expanded)
                valueLabel.setText("[...]");
        }else{
            if(node.valueIsString()){
                leftQuote2.setText("\"");
                rightQuote2.setText("\"");
            }
            valueLabel.setText(node.valueIsNull()?"null":node.getValue().toString());
        }

        if(node.isRoot()){
            keyLabel.setText(node.getkey());
        }else if(node.getParent().valueIsList()){
            keyLabel.setText(node.getParent().getIndex(node)+"");
        }else{
            leftQuote1.setText("\"");
            rightQuote1.setText("\"");
            keyLabel.setText(node.getkey());
        }

        keyPanel.add(leftQuote1);
        keyPanel.add(keyLabel);
        keyPanel.add(rightQuote1);

        valuePanel.add(leftQuote2);
        valuePanel.add(valueLabel);
        valuePanel.add(rightQuote2);

        panel.add(keyPanel);
        panel.add(splitLabel);
        panel.add(valuePanel);
        panel.add(lengthLabel);

        ((FlowLayout)panel.getLayout()).setVgap(0);
        ((FlowLayout)keyPanel.getLayout()).setHgap(0);
        ((FlowLayout)keyPanel.getLayout()).setVgap(0);
        ((FlowLayout)valuePanel.getLayout()).setHgap(0);
        ((FlowLayout)valuePanel.getLayout()).setVgap(0);
        keyPanel.setOpaque(false);
        valuePanel.setOpaque(false);
        if(sel){
            panel.setBackground(getBackgroundSelectionColor());
        }else{
            panel.setOpaque(false);
        }
        return panel;
    }
    
}