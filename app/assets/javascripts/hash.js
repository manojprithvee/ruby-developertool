$(document).ready(function () {
$('#text').on("input",function () {
    $.ajax({url: "https://developertoolsphp.herokuapp.com/hash.php?string="+$(this).val(), success: function(result){
        $("#output").html(result)
    }
});
});
});