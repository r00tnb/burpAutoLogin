package burp.autologin.UI.components;

import java.util.Vector;

import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

public class MyTable extends JTable {
    public MyTable() {
        
    }

    public void setHeader(String... headerList){
        ((DefaultTableModel) getModel()).setDataVector(null, headerList);
    }

    /**
     * 删除所有行
     */
    public void removeRowAll(){
        int count = getRowCount();
        while(count-- > 0){
            removeRow(count);
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        // TODO Auto-generated method stub
        return false;
    }

    /**
     * 选中指定列中与obj相等的行
     * @param column 指定的列索引（从0开始）
     * @param obj 指定比较的对象
     */
    public void selectRowsByColumn(int column, Object obj){
        for(int i=getRowCount()-1;i>=0;i--){
            if(getValueAt(i, column).equals(obj)){
                setRowSelectionInterval(i, i);
            }
        }
    }

    /**
     * 更新指定行的数据
     * @param row 指定行号
     * @param objList 行数据列表
     */
    public void updateRow(int row, Object... objList){
        ((DefaultTableModel) getModel()).insertRow(row, objList);
        removeRow(row+1);
    }

    /**
     * 删除指定的列中与obj相等的行
     * @param column 指定的列索引（从0开始）
     * @param obj 指定比较的对象
     */
    public void removeRowByColumn(int column, Object obj){
        for(int i=getRowCount()-1;i>=0;i--){
            if(getValueAt(i, column).equals(obj)){
                removeRow(i);
            }
        }
    }

    public void hiddenColumn(int column){
        TableColumn tc = getColumnModel().getColumn(column);
        tc.setWidth(0);
        tc.setMaxWidth(0);
        tc.setMinWidth(0);
        tc.setPreferredWidth(0);

        tc = getTableHeader().getColumnModel().getColumn(column);
        tc.setWidth(0);
        tc.setMaxWidth(0);
        tc.setMinWidth(0);
        tc.setPreferredWidth(0);
    }

    public void removeRow(int row){
        ((DefaultTableModel) getModel()).removeRow(row);
    }

    public void removeSelectedRows(){
        int[] rows = getSelectedRows();
        for(int i=rows.length-1;i>=0;i--){
            removeRow(rows[i]);
        }
    }

    public void setHeaderWidth(int... widths){
        for(int i=0;i<getColumnCount() && i<widths.length;i++){
            TableColumn column = getColumnModel().getColumn(i);
            column.setPreferredWidth(widths[i]);
        }
    }

    public void addRow(Object... objList){
        if(getColumnCount()<objList.length) return;
        DefaultTableModel model = (DefaultTableModel) getModel();
        Vector<Object> data = new Vector<>();
        for(int i=0;i<getColumnCount();i++){
            if(i<objList.length){
                data.add(objList[i]);
            }else{
                data.add("");
            }
        }
        model.addRow(data);
    }
}