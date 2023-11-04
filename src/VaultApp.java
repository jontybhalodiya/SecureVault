import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.ResultSet;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class VaultApp extends JFrame {
    private static SecretKey secretKey;
    private JTextArea vaultTextArea;

    private static Connection connection;
    private int currentUserId; // Store the currently logged-in user's ID
    private PrivateKey userPrivateKey; // Private key for RSA encryption
    private PublicKey userPublicKey; // Public key for RSA encryption

    private JTextField usernameField;
    private JPasswordField passwordField;

    public static void main(String[] args) {
        initializeSecretKey();
        initializeDatabase();
        SwingUtilities.invokeLater(() -> new VaultApp());
    }

    private VaultApp() {
        super("Secure Vault");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(300, 200);

        JLabel usernameLabel = new JLabel("Username:");
        usernameField = new JTextField(20);

        JLabel passwordLabel = new JLabel("Password:");
        passwordField = new JPasswordField(20);

        JButton loginButton = new JButton("Login");
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                login(usernameField.getText(), new String(passwordField.getPassword()));
            }
        });

        JButton registerButton = new JButton("Register");
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                register(usernameField.getText(), new String(passwordField.getPassword()));
            }
        });

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(3, 2));
        panel.add(usernameLabel);
        panel.add(usernameField);
        panel.add(passwordLabel);
        panel.add(passwordField);
        panel.add(loginButton);
        panel.add(registerButton);

        add(panel);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private static void initializeSecretKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void initializeDatabase() {
        try {
            // Make sure to provide the correct database URL, username, and password.
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3307/securevault", "root", "root");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void login(String username, String password) {
        // Verify user credentials against the database.
        String query = "SELECT id, rsa_public_key, rsa_private_key FROM users WHERE username = ? AND password = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, password);
            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                currentUserId = resultSet.getInt("id"); // Store the user ID
                userPublicKey = getPublicKeyFromString(resultSet.getString("rsa_public_key"));
                userPrivateKey = getPrivateKeyFromString(resultSet.getString("rsa_private_key"));
                showVaultUI(username);
                dispose();
            } else {
                showAlert("Login Failed", "Invalid username or password.");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean isUsernameTaken(String username) {
        String query = "SELECT id FROM users WHERE username = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            return resultSet.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false; // Handle the exception appropriately in your application
        }
    }


    private void register(String username, String password) {
        // Check if the username is already in use
        if (isUsernameTaken(username)) {
            showAlert("Registration Failed", "Username already exists.");
            return;
        }

        // Generate an RSA key pair for the user
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            userPublicKey = keyPair.getPublic();
            userPrivateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            showAlert("Registration Failed", "Unable to generate RSA key pair.");
            return;
        }

        // Store the user's RSA key pair securely in the database
        String query = "INSERT INTO users (username, password, rsa_public_key, rsa_private_key) VALUES (?, ?, ?, ?)";
        try (PreparedStatement preparedStatement = connection.prepareStatement(query, PreparedStatement.RETURN_GENERATED_KEYS)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, password);
            preparedStatement.setString(3, getStringFromPublicKey(userPublicKey));
            preparedStatement.setString(4, getStringFromPrivateKey(userPrivateKey));
            preparedStatement.executeUpdate();

            ResultSet generatedKeys = preparedStatement.getGeneratedKeys();
            if (generatedKeys.next()) {
                currentUserId = generatedKeys.getInt(1); // Store the user ID
                showAlert("Registration Successful", "You can now log in.");
            } else {
                showAlert("Registration Failed", "Unable to retrieve user ID.");
            }
        } catch (SQLException e) {
            showAlert("Registration Failed", "Username already exists.");
        }
    }

    private void showVaultUI(String username) {
        JFrame vaultFrame = new JFrame("Vault for " + username);
        vaultFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        vaultFrame.setSize(400, 300);

        vaultTextArea = new JTextArea(10, 40);

        vaultTextArea.setEditable(false);

        JScrollPane scrollPane = new JScrollPane(vaultTextArea);

        JButton addButton = new JButton("Add Content");
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Logic to add content to the vault here.
                String websiteURL = JOptionPane.showInputDialog("Enter Website URL:");
                String siteUsername = JOptionPane.showInputDialog("Enter Username:");
                String sitePassword = JOptionPane.showInputDialog("Enter Password");

                // Encrypt data using RSA public key
                try {
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, userPublicKey);
                    byte[] encryptedURL = cipher.doFinal(websiteURL.getBytes());
                    byte[] encryptedUsername = cipher.doFinal(siteUsername.getBytes());
                    byte[] encryptedPassword = cipher.doFinal(sitePassword.getBytes());

                    // Store encrypted data in the database
                    String insertQuery = "INSERT INTO website_credentials (user_id, encrypted_url, encrypted_username, encrypted_password) VALUES (?, ?, ?, ?)";

                    try (PreparedStatement preparedStatement = connection.prepareStatement(insertQuery)) {
                        preparedStatement.setInt(1, currentUserId); // Use the stored user ID
                        preparedStatement.setBytes(2, encryptedURL);
                        preparedStatement.setBytes(3, encryptedUsername);
                        preparedStatement.setBytes(4, encryptedPassword);
                        preparedStatement.executeUpdate();
                        showAlert("Data Added", "Website credentials added to the vault.");
                        refreshVaultUI();
                    } catch (SQLException ex) {
                        ex.printStackTrace();
                        showAlert("Error", "Failed to add data to the vault.");
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                    showAlert("Error", "Failed to encrypt data.");
                }
            }
        });

        JButton logoutButton = new JButton("Logout");
        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                vaultFrame.dispose();
            }
        });

        // Fetch and display user's saved details
        StringBuilder userDetails = new StringBuilder();
        userDetails.append("Saved Details:\n");

        try {
            String selectQuery = "SELECT encrypted_url, encrypted_username, encrypted_password FROM website_credentials WHERE user_id = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(selectQuery)) {
                preparedStatement.setInt(1, currentUserId);
                ResultSet resultSet = preparedStatement.executeQuery();

                while (resultSet.next()) {
                    // Decrypt data using RSA private key
                    byte[] encryptedURL = resultSet.getBytes("encrypted_url");
                    byte[] encryptedUsername = resultSet.getBytes("encrypted_username");
                    byte[] encryptedPassword = resultSet.getBytes("encrypted_password");

                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, userPrivateKey);
                    String decryptedURL = new String(cipher.doFinal(encryptedURL));
                    String decryptedUsername = new String(cipher.doFinal(encryptedUsername));
                    String decryptedPassword = new String(cipher.doFinal(encryptedPassword));

                    userDetails.append("Website URL: ").append(decryptedURL).append("\n");
                    userDetails.append("Username: ").append(decryptedUsername).append("\n");
                    userDetails.append("Password: ").append(decryptedPassword).append("\n\n");
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            showAlert("Error", "Failed to fetch saved details.");
        }

        vaultTextArea.setText(userDetails.toString());

        JPanel vaultPanel = new JPanel();
        vaultPanel.setLayout(new BorderLayout());
        vaultPanel.add(scrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(addButton);
        buttonPanel.add(logoutButton);

        vaultPanel.add(buttonPanel, BorderLayout.SOUTH);

        vaultFrame.add(vaultPanel);
        vaultFrame.setLocationRelativeTo(this);
        vaultFrame.setVisible(true);
    }

    private void showAlert(String title, String content) {
        JOptionPane.showMessageDialog(this, content, title, JOptionPane.INFORMATION_MESSAGE);
    }

    // Utility method to convert PublicKey to String
    private String getStringFromPublicKey(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    // Utility method to convert PrivateKey to String
    private String getStringFromPrivateKey(PrivateKey privateKey) {
        byte[] privateKeyBytes = privateKey.getEncoded();
        return Base64.getEncoder().encodeToString(privateKeyBytes);
    }

    private void refreshVaultUI() {
        StringBuilder userDetails = new StringBuilder();
        userDetails.append("Saved Details:\n");

        try {
            String selectQuery = "SELECT encrypted_url, encrypted_username, encrypted_password FROM website_credentials WHERE user_id = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(selectQuery)) {
                preparedStatement.setInt(1, currentUserId);
                ResultSet resultSet = preparedStatement.executeQuery();

                while (resultSet.next()) {
                    byte[] encryptedURL = resultSet.getBytes("encrypted_url");
                    byte[] encryptedUsername = resultSet.getBytes("encrypted_username");
                    byte[] encryptedPassword = resultSet.getBytes("encrypted_password");

                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, userPrivateKey);
                    String decryptedURL = new String(cipher.doFinal(encryptedURL));
                    String decryptedUsername = new String(cipher.doFinal(encryptedUsername));
                    String decryptedPassword = new String(cipher.doFinal(encryptedPassword));

                    userDetails.append("Website URL: ").append(decryptedURL).append("\n");
                    userDetails.append("Username: ").append(decryptedUsername).append("\n");
                    userDetails.append("Password: ").append(decryptedPassword).append("\n\n");
                }
                vaultTextArea.setText(userDetails.toString()); // Update the vault UI
            } catch (Exception ex) {
                ex.printStackTrace();
                showAlert("Error", "Failed to fetch saved details.");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Utility method to convert String to PublicKey
    private PublicKey getPublicKeyFromString(String publicKeyString) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    // Utility method to convert String to PrivateKey
    private PrivateKey getPrivateKeyFromString(String privateKeyString) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
