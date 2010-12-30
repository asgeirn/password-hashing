<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Failure</title>
<style type="text/css">
BODY {
    background-color: #FF3366;
    font-family: Segoe UI, Verdana, sans-serif;
}
</style>
</head>
<body>
<h1>Failure</h1>
<p>Sadly it didn't work.  Here's why:</p>
<pre><%= request.getParameter("message") %></pre>
</body>
</html>