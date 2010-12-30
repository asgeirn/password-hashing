<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Success!</title>
<style type="text/css">
BODY {
    background-color: #99ff33;
    font-family: Segoe UI, Verdana, sans-serif;
}
</style>
</head>
<body>
<h1>Success!</h1>
<p>User name: <%= session.getAttribute("user") %></p>
<p>Password: <%= session.getAttribute("password") %></p>
<p>Logged in: <%= String.format("%tc", session.getAttribute("login")) %></p>
<pre><%= request.getParameter("message") %></pre>
</body>
</html>