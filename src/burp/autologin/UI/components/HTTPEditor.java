package burp.autologin.UI.components;

import java.awt.Color;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JTextArea;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Caret;
import javax.swing.text.Highlighter;
import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;

import burp.Util.TempEntry;
import burp.Util.Util;
import burp.autologin.core.AutoLoginItem;
import burp.autologin.core.Message;

public class HTTPEditor extends JTextArea {

    private Message message;

    /**记录上一次选中文本的高亮对象 */
    private Object lastHighlight = null;

    public HTTPEditor() {
        setEditable(false);
        setLineWrap(true);

        getCaret().addChangeListener(new ChangeListener(){

            @Override
            public void stateChanged(ChangeEvent e) {
                // TODO Auto-generated method stub
                int start = getCaret().getDot(), end = getCaret().getMark();
                if(start > end){
                    int temp = start;
                    start = end;
                    end = temp;
                }
                if(end-start < 1) return;
                if(lastHighlight != null){
                    getHighlighter().removeHighlight(lastHighlight);
                }
                DefaultHighlightPainter p = new DefaultHighlightPainter(getSelectionColor());
                try {
                    lastHighlight = getHighlighter().addHighlight(start, end, p);
                } catch (BadLocationException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
            
        });
    }

    public void setMessage(Message message) {
        this.message = message;
        try {
            setText(new String(message.getResponse(), message.getResponseCharset()));
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public Message getMessage() {
        return message;
    }

    /**
     * 高亮关键字
     */
    public void highlightKeyword() {
        if (message == null)
            return;

        Map<Integer, Integer> keywords = message.getTokenSearchModel().searchTokenIndexs();
        Highlighter high = getHighlighter();
        high.removeAllHighlights();
        DefaultHighlightPainter p = new DefaultHighlightPainter(Color.RED);
        int once = 1;
        for (Entry<Integer, Integer> indexs : keywords.entrySet()) {
            try {
                high.addHighlight(indexs.getKey(), indexs.getValue(), p);
                while(once-- > 0){
                    setCaretPosition(indexs.getKey());
                }
            } catch (BadLocationException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    public TempEntry<String, Pattern> getSelectedTextPattern() {
        // TODO Auto-generated method stub
        Caret caret = getCaret();
        TempEntry<String, Pattern> tempEntry = new TempEntry<>();
        int start = caret.getDot(), end = caret.getMark();
        if(start > end){
            int temp = start;
            start = end;
            end = temp;
        }
        
        Pattern pattern = Util.getPatternFromSelectedBounds(getText(), start, end);
        if(pattern != null){
            tempEntry.setKey("token_"+Util.randomString(5));
            tempEntry.setValue(pattern);
        }

        return tempEntry;
    }
}