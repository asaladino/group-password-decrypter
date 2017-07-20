package com.codingsimply.apps.group_password_decrypter.controller;

import com.codingsimply.apps.group_password_decrypter.utility.GroupPassword;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;

/**
 * Main window controller for the form.
 */
public class MainController {

    /**
     * Field to enter the encrypted string.
     */
    @FXML
    private TextField encryptedTextField;

    /**
     * Field to output the decrypted string.
     */
    @FXML
    private TextField decryptedTextField;

    /**
     * For displaying any errors.
     */
    @FXML
    private Label messageLabel;

    /**
     * Action for decrypting the string.
     */
    public void decrypt() {
        try {
            String value = GroupPassword.decrypt(encryptedTextField.getText());
            decryptedTextField.setText(value);
            messageLabel.setText("");
        } catch (Exception e) {
            messageLabel.setText(e.getMessage());
        }
    }

    /**
     * Action for closing the app.
     */
    public void exit() {
        System.exit(1);
    }
}
