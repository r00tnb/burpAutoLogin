package jsoncomp.json;

import java.io.IOException;
import java.io.StringReader;

import jsoncomp.json.parser.Parser;
import jsoncomp.json.tokenizer.ReaderChar;
import jsoncomp.json.tokenizer.TokenList;
import jsoncomp.json.tokenizer.Tokenizer;


public class JSONParser {
    private Tokenizer tokenizer = new Tokenizer();

    private Parser parser = new Parser();

    public Object fromJSON(String json) throws IOException {
        ReaderChar charReader = new ReaderChar(new StringReader(json));
        TokenList tokens = tokenizer.getTokenStream(charReader);
        return parser.parse(tokens);
    }
}
