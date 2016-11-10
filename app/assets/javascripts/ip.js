$(document).ready(function () {
    $.ajax({url: "ip.php", success: function(result){
        $("#output").html(result)
    }
});
});