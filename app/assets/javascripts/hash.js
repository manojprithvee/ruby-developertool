$(document).ready(function () {
$('#text').on("input",function () {
    $.ajax({url: "http://developertool.biz/hash.php?string="+$(this).val(), success: function(result){
        $("#output").html(result)
    }
});
});
});