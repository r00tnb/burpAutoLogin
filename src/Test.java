import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.GridLayout;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JTree;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.tree.TreePath;

import jsoncomp.JsonModel;
import jsoncomp.JsonNode;
import jsoncomp.JsonTree;
import jsoncomp.JsonTreeCellRender;

public class Test {
    public static void main(String[] args) {
        JFrame frame = new JFrame("test");
        JPanel panel = new JPanel();

        JTree tree = new JTree();
        tree.setEditable(true);

        panel.setLayout(new GridLayout(1, 1));
        panel.setPreferredSize(new Dimension(400, 400));
        JsonTree jsonTree = new JsonTree();
        jsonTree.expandAll();
        panel.add(jsonTree);
        panel.add(tree);
        frame.setContentPane(panel);
        frame.setSize(400, 400);
        frame.setLocationRelativeTo(null);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setVisible(true);

    }
}