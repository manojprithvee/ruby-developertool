$(document).ready(function () {
$("#Submit").on("click",function(){
    console.log("manoj")
    urls="'" + $("#url").val().split(",").join("','") + "'";
    xpaths=$("#xpath").val()
    $('#output').load(encodeURI('https://query.yahooapis.com/v1/public/yql?q=select * from html where url in ('+urls+') and xpath="'+xpaths+'"&format=json'));
});
});