
    $.ajax({url: "http://developertool.biz/ip.php", success: function(result){
        $("#output").html(result)
    }
});