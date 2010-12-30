package no.twingine.passwords;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@SuppressWarnings("serial")
public class PasswordsServlet extends HttpServlet {
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String action = req.getParameter("action");
        if ("salt".equalsIgnoreCase(action)) {
            resp.setContentType("text/javascript");
            resp.setDateHeader("Expires", System.currentTimeMillis() + 1);
            resp.setHeader("Pragma", "no-cache,max-age=0,must-revalidate");
            resp.getWriter().println("var salt = \"" + req.getRemoteAddr() + "\";");
            return;
        }
        resp.setContentType("text/plain");
        PrintWriter writer = resp.getWriter();
        writer.println("Hello, world");
        try {
            String message = req.getParameter("message");
            byte[] ciphertext = new BigInteger(message, 16).toByteArray();
            Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(
                    new BigInteger(
                            "8de7066f67be16fcacd05d319b6729cd85fe698c07cec504776146eb7a041d9e3cacbf0fcd86441981c0083eed1f8f1b18393f0b186e47ce1b7b4981417b491",
                            16),
                    new BigInteger(
                            "59fed719f8959a468de367f77a33a7536d53b8e4d25ed49ccc89a94cd6899da90415623fb73386e9635034fb65ad5f248445a1c66703f760d64a8271ad342b1",
                            16));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] data = cipher.doFinal(ciphertext);
            reverse(data);
            int len = data.length;
            while (data[len - 1] == 0)
                --len;
            String plaintext = new String(data, 0, len);
            writer.println(plaintext);
        } catch (Exception e) {
            e.printStackTrace(writer);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        StringWriter s = new StringWriter();
        PrintWriter writer = new PrintWriter(s);
        try {
            @SuppressWarnings("unchecked")
            Map<String, String[]> m = req.getParameterMap();
            for (Map.Entry<String, String[]> e : m.entrySet())
                writer.printf("%s=%s\n", e.getKey(), Arrays.toString(e.getValue()));
            String action = req.getParameter("action");
            if ("register".equalsIgnoreCase(action)) {
                assert "RSA".equals(req.getParameter("confirm")) : "Unexpected encryption mode";
                String encrypted = req.getParameter("password");
                byte[] ciphertext = new BigInteger(encrypted, 16).toByteArray();
                Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(
                        new BigInteger(
                                "beea63f513bf2d53ba8f8e571bfea6115b0f3e5882738990862129442d0e07c926fb1099f1be987e92f35abe8b92b2d42fe6d9dd3ea1d4c444506af68d9b2742ebf9842d23863d05b5daa8234626e67164d003bb7230cf3f74f695a986ce59a23cb9a63bc5aee3c59ab6f53c5f2b2a35bf1cbe9adf3110e75fe0647d26d3e935",
                                16),
                        new BigInteger(
                                "70808d273f39304a44085314aef01d640b6ffbf0873f9fb8a59dcc6280548ca9919cd7ca418f2b5eecd2ee75ab3e7a2d8a2dfe6607f141d090a62dd7055e43619b8b1866b6e1c7405527822efa20298c56ff5f8851b96200e49643a52fbc8e1ebd9f4cc16ce4de65c2f6dc5f60ed8d2074ec7ed967ea30655d09b160c1829ce3",
                                16));
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] data = cipher.doFinal(ciphertext);
                reverse(data);
                int len = data.length;
                while (data[len - 1] == 0)
                    --len;
                String password = new String(data, 0, len);
                writer.println(password);
                if (password.startsWith("OK:")) {
                    HttpSession session = req.getSession(true);
                    session.setAttribute("user", req.getParameter("user"));
                    session.setAttribute("password", password.substring(3));
                    resp.sendRedirect(resp.encodeRedirectURL("success.jsp?message=" + URLEncoder.encode(String.format("Successfully registered user %s with password hash %s%n", req.getParameter("user"), password.substring(3)), "US-ASCII")));
                } else {
                    resp.sendRedirect(resp.encodeRedirectURL("failure.jsp?message=" + URLEncoder.encode("Failed to decrypt incoming password hash", "US-ASCII")));
                }

            } else if ("login".equalsIgnoreCase(action)) {
                Mac mac = Mac.getInstance("HmacSHA512");
                SecretKey key = new SecretKeySpec(req.getRemoteAddr().getBytes(), "HmacSHA512");
                mac.init(key);
                HttpSession session = req.getSession(false);
                String user = (String) session.getAttribute("user");
                String password = (String) session.getAttribute("password");
                byte[] hash = mac.doFinal(password.getBytes());
                String expected = new BigInteger(1, hash).toString(16);
                writer.printf("expect: %s%nactual: %s%n", expected, req.getParameter("password"));
                if (!user.equalsIgnoreCase(req.getParameter("user"))) {
                    resp.sendRedirect(resp.encodeRedirectURL("failure.jsp?message=" + URLEncoder.encode(String.format("Wrong user name %s -- expected %s", req.getParameter("user"), user), "US-ASCII")));
                }
                if (!expected.equals(req.getParameter("password"))) {
                    resp.sendRedirect(resp.encodeRedirectURL("failure.jsp?message=" + URLEncoder.encode(String.format("Wrong password %s -- expected %s", req.getParameter("password"), expected), "US-ASCII")));
                }
                session.setAttribute("login", System.currentTimeMillis());
                resp.sendRedirect(resp.encodeRedirectURL("success.jsp?message=" + URLEncoder.encode(String.format("Successfully validated credentials for user %s%n", user), "US-ASCII")));

            } else if ("validate".equalsIgnoreCase(action)) {
                HttpSession session = req.getSession(false);
                String user = (String) session.getAttribute("user");
                if (user != null)
                    writer.printf("user = %s%n", user);
                String password = (String) session.getAttribute("password");
                if (password != null)
                    writer.printf("password = %s%n", password);
                Long login = (Long) session.getAttribute("login");
                if (login != null)
                    writer.printf("Logged in at %tc%n", login);

                resp.sendRedirect(resp.encodeRedirectURL("success.jsp?message=" + URLEncoder.encode(s.toString(), "US-ASCII")));
            }
        } catch (Exception e) {
            e.printStackTrace(writer);
            resp.sendRedirect(resp.encodeRedirectURL("failure.jsp?message=" + URLEncoder.encode(s.toString(), "US-ASCII")));
        }
    }

    public static void main(String[] args) throws Exception {
        byte[] ciphertext = new BigInteger(
                "02b87f916cc87db42fcae6f95b3680feda647e04ea3757e040bef7921e9e4fb7f8ea1c36afdabd2133ddd4e1ad9d3523eae8310da6873789ce632784428000e2",
                16).toByteArray();
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(
                new BigInteger(
                        "8de7066f67be16fcacd05d319b6729cd85fe698c07cec504776146eb7a041d9e3cacbf0fcd86441981c0083eed1f8f1b18393f0b186e47ce1b7b4981417b491",
                        16),
                new BigInteger(
                        "59fed719f8959a468de367f77a33a7536d53b8e4d25ed49ccc89a94cd6899da90415623fb73386e9635034fb65ad5f248445a1c66703f760d64a8271ad342b1",
                        16));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] data = cipher.doFinal(ciphertext);
        reverse(data);
        int len = data.length;
        while (data[len - 1] == 0)
            --len;
        String plaintext = new String(data, 0, len);
        System.out.println(plaintext);

    }

    /**
     * <p>
     * Reverses the order of the given array.
     * </p>
     *
     * <p>
     * This method does nothing for a <code>null</code> input array.
     * </p>
     *
     * @param array
     *            the array to reverse, may be <code>null</code>
     */
    public static void reverse(byte[] array) {
        if (array == null) {
            return;
        }
        int i = 0;
        int j = array.length - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
        }
    }

}
