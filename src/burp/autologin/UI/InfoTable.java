package burp.autologin.UI;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.List;
import java.util.Vector;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

import burp.autologin.UI.components.MyTable;
import burp.autologin.core.*;

public class InfoTable extends MyTable {

    public InfoTable() {
        setModel(new DefaultTableModel(){
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                // TODO Auto-generated method stub
                if(columnIndex == 2)
                    return Boolean.class;
                return super.getColumnClass(columnIndex);
            }
        }); 

        setHeader("Name", "Domain", "Enabled", "obj");
        hiddenColumn(3);
        setRowHeight(30);
        setHeaderWidth(20, 250, 10);
        getModel().addTableModelListener(new TableModelListener() {

            @Override
            public void tableChanged(TableModelEvent e) {
                // TODO Auto-generated method stub
                int row = e.getFirstRow();
                int column = e.getColumn();
                if(e.getType() == TableModelEvent.UPDATE){
                    AutoLoginItem item = getSelectedItem();
                    Object value = getValueAt(row, column);
                    switch (column) {
                        case 0:
                            item.setName(value.toString());
                            break;
                        case 1:
                            item.setDomain(value.toString());
                            break;
                        case 2:
                            item.setEnabled((Boolean)value);
                        default:
                            break;
                    }
                }
            }
            
        });
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        // TODO Auto-generated method stub
        return true;
    }

    public void addRow(AutoLoginItem item){
        addRow(item.getName(), item.getDomain(), item.isEnabled(), item);
    }

    public List<AutoLoginItem> getItemList(){
        List<AutoLoginItem> result = new Vector<>();
        for(int i=0;i<getRowCount();i++){
            result.add((AutoLoginItem)getValueAt(i, 3));
        }
        return result;
    }

    public AutoLoginItem getSelectedItem(){
        return (AutoLoginItem)getValueAt(getSelectedRow(), 3);
    }

    public List<AutoLoginItem> getSelectedItems(){
        List<AutoLoginItem> result = new Vector<>();
        for(int i : getSelectedRows()){
            result.add((AutoLoginItem)getValueAt(i, 3));
        }
        return result;
    }
}