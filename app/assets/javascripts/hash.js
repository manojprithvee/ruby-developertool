$(document).ready(function () {
$('#text').on("input",function () {
    $.ajax({url: "https://developertool.biz/hash.php?string="+$(this).val(), success: function(result){
        $("#output").html(result)
    }
});
});
});