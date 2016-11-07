$(document).ready(function () {
$("#butt").on("click",function() {
    var text = "";
    length=$("#length").val()
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()_+-={}|[]\:\";'<>?,./";
    for(var i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    $("#password").val(text);;
});});