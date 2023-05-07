<?php
session_start();

include("connection.php");
include("functions.php");

if($_SERVER['REQUEST_METHOD'] == "POST" )
{
    //something was posted
    $user_name = $_POST['user_name'];
    $password = $_POST['password'];

    if(!empty($user_name) && !empty($password) )
    {
        //save to database
        $user_id = random_num(20);
        $query = "insert into users (user_id, user_name, password) values ('$user_id', '$user_name', '$password') ";

        mysqli_query($con, $query);

        header("Location:login.php");
        die;
    }else
    {
        echo "Please enter some valid information";
    }
}
?>

<!DOCTYPE html>
<head>
  <title>sign up</title>
  <link rel="stylesheet" type="text/css" href="style.css" media="screen" />
</head>
<title> sign up page </title>
<body>
    <h3>sign up page</h3>
    <style type= "text/css" >
    #text{
        height: 25px;
        border-radius: 5px;
        padding: 4px;
        border: solid thin #aaa;
        width: 100%;

    }
    #button{
        padding:10px;
        width:100px;
        color:white;
        background-color: lightblue;
        border: none;

    }
    #box{
        background-color: grey;
        margin: auto;
        width: 300px;
        padding:20px;
    }
    </style>
    <div id="box">
        <form method="post">
            <div style="font-size: 20px; margin:10px; color:white";>login</div>
            <input id="text" type="text" name="user_name"><br><br>
            <input id="text" type="text" name="password"><br><br>
            <input id="button" type="submit" value="signup" style="color:black" ><br><br>
            <a href=login.php>login</a><br><br>
        </form>
        
    </div>
</body>
</html>
