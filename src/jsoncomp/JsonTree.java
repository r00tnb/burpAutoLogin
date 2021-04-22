package jsoncomp;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JTree;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultTreeSelectionModel;
import javax.swing.tree.TreePath;

public class JsonTree extends JTree {

    {// 初始化对象
        this.setCellRenderer(new JsonTreeCellRender());
        this.setCellEditor(new JsonTreeCellEditor());
        setShowsRootHandles(true);
        setEditable(true);

        addKeyListener(new KeyListener(){

			@Override
			public void keyTyped(KeyEvent e) {
                // TODO Auto-generated method stub
                if(getSelectionPath() == null || !JsonTree.this.isEditable()) return;
                JsonNode node = (JsonNode)(getSelectionPath().getLastPathComponent());
                JsonNode parent = node.getParent();
                Enumeration<? extends TreePath> expandedPaths = getExpandedDescendants(new TreePath(parent == null?node.getPath():parent.getPath()));
                if(e.getKeyChar() == KeyEvent.VK_BACK_SPACE || e.getKeyChar() == KeyEvent.VK_DELETE){
                    if(!node.isRoot()){
                        node.removeSelf();
                        JsonNode right = node.rightBro;
                        ((JsonModel)getModel()).reload(parent);
                        if(right != null)
                            setSelectionPath(new TreePath(right.getPath()));
                    }
                }else if(e.getKeyChar() == KeyEvent.VK_ENTER){
                    node.append(JsonNode.randomKey(), "test");
                    ((JsonModel)getModel()).reload(parent == null?node:parent);
                    setSelectionPath(new TreePath(node.getPath()));
                }
                
                while(expandedPaths.hasMoreElements()){
                    expandPath(expandedPaths.nextElement());
                }
                
			}

			@Override
			public void keyPressed(KeyEvent e) {
				// TODO Auto-generated method stub
				
			}

			@Override
			public void keyReleased(KeyEvent e) {
				// TODO Auto-generated method stub
				
			}
            
        });
    }

    public JsonTree(){
        setModel(new JsonModel("{\"msg\":\"ok\", \"code\":200, \"data\":[{\"id\": 1}, {\"id\":2}, {\"id\":3}]}"));
    }
    public JsonTree(String jsonString){
        setModel(new JsonModel(jsonString));
    }
    public JsonTree(JsonModel model){
        setModel(model);
    }
    
    public void expandAll(){
        expandOrCollapseAll((JsonNode)(getModel().getRoot()), true);
    }
    public void collapseAll(){
        expandOrCollapseAll((JsonNode)(getModel().getRoot()), false);
    }

    public void expandOrCollapseAll(JsonNode node, boolean expand){
        if(node == null) return;
        TreePath path = new TreePath(node.getPath());
        if(!node.isLeaf()){
            for(Enumeration<? extends JsonNode> e=node.children();e.hasMoreElements();){
                expandOrCollapseAll(e.nextElement(), expand);
            }
            if(expand)
                expandPath(path);
            else
                collapsePath(path);
        }
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return ((JsonModel)getModel()).getRoot().toString();
    }

}