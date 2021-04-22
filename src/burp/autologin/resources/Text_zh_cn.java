package burp.autologin.resources;

import java.util.ListResourceBundle;

public class Text_zh_cn extends ListResourceBundle {
    private final Object[][] data = {
        {"add session invalid rule", "添加session失效验证规则"},
        {"edit session invalid rule", "修改session失效验证规则"},
        {"delete seleted items", "删除选中项"},
        {"edit seleted item", "编辑选中项"},
        {"type", "类型"},
        {"expression", "表达式"},
        {"add", "添加"},
        {"session invalid rule list", "失效验证规则列表"},
        {"regexp syntax error!", "正则表达式语法错误！"},
        {"add token update rule", "添加token更新规则"},
        {"update all token in request", "更新请求中的同名token值"},
        {"it will update token in request's query parameters,POST parameters,header and cookie.", "更新请求参数、请求头中、cookie中的同名token值"},
        {"token update regexp", "token更新正则表达式"},
        {"token name", "token名称"},
        {"describe", "描述"},
        {"use url encode", "使用URL编码"},
        {"ok", "确定"},
        {"replace result use url encoding", "替换结果使用URL编码"},
        {"token is null tips,you need to set token first!", "token为空！请先配置token"},
        {"it is used to search token in request for updating.", "用于在请求中搜索需要被更新的token值，并替换成指定token"},
        {"edit token update rule", "修改token更新规则"},
        {"configurate token", "配置token"},
        {"name", "名称"},
        {"regexp", "正则表达式"},
        {"name or regexp is null!", "名称或正则表达式为空！"},
        {"token is existing!", "存在同名token！"},
        {"regexp for search", "搜索正则表达式"},
        {"all search token", "所有搜索token"},
        {"edit and record login sequence", "编辑/录制登录序列"},
        {"recording login sequence from proxy", "从proxy抓取登录序列"},
        {"only record the requests of same domain", "只抓取同域请求"},
        {"clear", "清空"},
        {"it will cover old settings", "这将覆盖旧的登录序列及修改！"},
        {"are you sure clear?", "确定清空吗？"},
        {"please record login sequence first", "请先录制登录序列！"},
        {"current token info", "当前token信息"},
        {"token update settings", "token更新规则设置"},
        {"session invalid setttings", "session失效验证设置"},
        {"add new item", "添加新项"},
        {"are you sure?it will remove all info of the item", "确定删除选中项？这将删除该项下的所有信息！"},
        {"update current request", "更新当前请求"},
        {"no login is built", "没有建立该域的登录过程！"},
        {"update request progress", "更新请求进度"},
        {"value", "值"},
        {"refresh session", "刷新session信息"},
        {"refresh session progress", "刷新session信息进度"},
        {"the token is not found!", "未搜索到该token！"},
        {"filter static message", "过滤静态消息"},
        {"generating a token replace rule by selection text", "生成token替换规则(需要选中文本)"},
        {"(need create login process)", "需要建立登录过程"},
        {"OK!you can edit this rule in AutoLogin panel", "已生成！你能在AutoLogin扩展配置页面修改生成的规则"},
        {"filter static message.Like .css, .js, .png .... and response body like image, script", "过滤静态消息，如以.css, .js, .png为后缀的请求，以及响应体能识别为图片或脚本类型的消息"},
        // sessionvalidatortype的name
        {"status code equal", "状态码等于"},
        {"status code not equal", "状态码不等于"},
        {"response header contains", "响应头部包含"},
        {"response header not contains", "响应头部不包含"},
        {"response body contains", "响应体包含"},
        {"response body not contains", "响应体不包含"},
        {"request contains", "完整请求中包含"},
        {"request not contains", "完整请求中不包含"}
    };

    @Override
    public Object[][] getContents() {
        // TODO Auto-generated method stub
        return data;
    }
}