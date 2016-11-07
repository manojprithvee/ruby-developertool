$(document).ready(function () {
$("#encode").on("click",function() {
    $("#url").val(encodeURI($("#url").val()))
});
$("#decode").on("click",function() {
     $("#url").val(decodeURI($("#url").val()))
});
});