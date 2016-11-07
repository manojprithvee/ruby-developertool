
<?php header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header('Access-Control-Allow-Origin: *'); ?>
<ul class="list-group">
<?php
if (isset($_GET['string'])){
    $hashs=array();
    foreach(hash_algos() as $value){
        echo '<li class="list-group-item">'.ucwords($value).'<span class="length pull-right badge">'.hash($value,$_GET['string']).'</span></li>';
    }
}
?>
</ul>