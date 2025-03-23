package mainView;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import main.Utils;

import java.io.*;
import java.nio.charset.StandardCharsets;


import static main.Utils.*;


public final class Controller {

  //radio buttons
  @FXML RadioButton size128;
  @FXML RadioButton size192;
  @FXML RadioButton size256;
  @FXML RadioButton usingFilesBtn;
  @FXML RadioButton usingWindowsBtn;

  //Load elements
  @FXML Button loadKeyBtn;
  @FXML TextArea keyLoadArea;

  @FXML Button openUnencryptedBtn;
  @FXML TextField openUnencryptedField;
  @FXML TextArea unencryptedTextArea;

  @FXML Button openEncryptedBtn;
  @FXML TextField openEncryptedField;
  @FXML TextArea encryptedTextArea;

  //Save elements
  @FXML Button saveKeyBtn;
  @FXML TextArea keySaveArea;

  @FXML TextField saveUnencryptedField;
  @FXML TextField saveEncryptedField;

  //Key gen elements
  @FXML Button genKey;
  @FXML TextArea keyGenArea;

  @FXML Button encryptBtn;
  @FXML Button decryptBtn;

  private byte[] unencryptedWindowBuffer;
  private byte[] encryptedWindowBuffer;
  private boolean defaultOutputSelection = true;

  private class Key {

    public Key(int length){
      this.length = length;
    }

    public byte[] val;
    public byte[][] expandedVal;
    public int Nr;
    public int Nk;
    public int length;
    public boolean isValid;
  }

  private Key key = new Key(128);

  /***
    Selects the button that is clicked and unselects all others.
    Updates the wanted keyLength accordingly
   * @param e event - pressing any of the 3 radio buttons
   */
  public void manageSizeButtons(ActionEvent e) {
    RadioButton[] sizeRadioButtons = {size128, size192, size256};
    RadioButton pressed = (RadioButton) e.getSource();

    switch(pressed.getId()) {
      case "size128":
        key.length = 128;
        break;
      case "size192":
        key.length = 192;
        break;
      case "size256":
        key.length = 256;
        break;
    }
    for (RadioButton button: sizeRadioButtons) {
      if (!button.equals(pressed)) {
        button.setSelected(false);
      }
    }
  }

  public void manageSelectionButtons(ActionEvent e) {
    RadioButton pressed = (RadioButton) e.getSource();
    if (pressed == usingFilesBtn) {
      defaultOutputSelection = true;
      usingWindowsBtn.setSelected(false);
    } else {
      defaultOutputSelection = false;
      usingFilesBtn.setSelected(false);
    }
  }

  /***
   * creates and saves key information based on user selection
   * @param e clicking the 'generate key' button
   */
  public void createKey(ActionEvent e) {

  }

  //TODO:

  /**
   * reloads the key to match the one in keyGenArea
   * @param e changing the keyGenArea
   */
  public void reloadKey(MouseEvent e) {
    final int keyHexaLength = keyGenArea.getLength();

    if(keyHexaLength == 32 || keyHexaLength == 48 || keyHexaLength == 64) {

      switch(keyHexaLength) {
        case 32:
          size128.setSelected(true);
          manageSizeButtons(new ActionEvent(size128, null));
          break;
        case 48:
          size192.setSelected(true);
          manageSizeButtons(new ActionEvent(size192, null));
          break;
        case 64:
          size256.setSelected(true);
          manageSizeButtons(new ActionEvent(size256, null));
          break;
      }
      String text = keyGenArea.getText();
      updateKeyBasedOn(text);
      } else {
        key.isValid = false;
      }
  }

  /**
   * Updates key based on the string in keyGenArea
   * @param text string from keyGenArea
   */
  public void updateKeyBasedOn(String text) {
    key.isValid = text.matches("^[0-9A-Fa-f]+$");

    if (key.isValid) {
      Byte[] temp = Utils.hexToBytes(text);
      key.val = new byte[temp.length];

      for (int i = 0; i < temp.length; i++) {
        key.val[i] = temp[i];
      }



    }
  }

  public void encrypt(ActionEvent e) {
    if(!key.isValid){
      showError("Key is invalid!", "Check whether its a valid hexadecimal string with 32, 48, 64 numbers");
      return;
    }

    if(defaultOutputSelection) {
      encryptBasedOnLoadedFiles();
    } else {
      encryptBasedOnWindows();
    }

  }

  public void encryptBasedOnLoadedFiles() {
    if(unencryptedWindowBuffer == null) {
      showError("Load a unencrypted file!", "No file was loaded");
      return;
    }

    byte[] paddedInput = padPKCS7(unencryptedWindowBuffer, 16);
    byte[] encryptedBytes = null; // TODO:

    encryptedWindowBuffer = encryptedBytes;

    encryptedTextArea.clear();
    encryptedTextArea.appendText(Utils.bytesToHex(encryptedBytes));
  }

  public void encryptBasedOnWindows() {
    String text = unencryptedTextArea.getText();
    byte[] paddedInput = padPKCS7(text.getBytes(StandardCharsets.UTF_8), 16);
    byte[] encryptedBytes = null; // TODO:

    encryptedTextArea.clear();
    encryptedTextArea.appendText(Utils.bytesToHex(encryptedBytes));
  }

  public void decrypt(ActionEvent e) {
    System.out.println(Utils.bytesToHex(key.val));
    if(!key.isValid) {
      showError("Key is invalid!", "Check whether its a valid hexadecimal string with 32, 48, 64 numbers");
      return;
    }

    if(defaultOutputSelection){
      decryptBasedOnLoadedFiles();
    } else {
      decryptBasedOnWindows();
    }
  }

  public void decryptBasedOnLoadedFiles() {
    if(encryptedWindowBuffer == null) {
      showError("Load a encrypted file!", "No file was loaded");
      return;
    }
    byte[] decryptedBytes = null;

    // Remove PKCS7 padding (if possible) and convert back to a readable string
    String decryptedText;
    try {
      decryptedText = new String(removePKCS7Padding(decryptedBytes), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException ex) {
      decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    try {
      unencryptedWindowBuffer = removePKCS7Padding(decryptedBytes);
    } catch (IllegalArgumentException ex) {
      unencryptedWindowBuffer = decryptedBytes;
    }

    unencryptedTextArea.clear();
    unencryptedTextArea.setText(decryptedText);
  }

  public void decryptBasedOnWindows() {
    String text = encryptedTextArea.getText();
    byte[] encryptedBytes;

    if(text.matches("^[0-9A-Fa-f]+$")) {
      Byte[] temp = Utils.hexToBytes(text);
      encryptedBytes = new byte[temp.length];

      for (int i = 0; i < temp.length; i++) {
        encryptedBytes[i] = temp[i];
      }

    } else {
      encryptedBytes = text.getBytes(StandardCharsets.UTF_8);
    }

    byte[] decryptedBytes = null;  //TODO:

    String decryptedText;
    try {
      decryptedText = new String(removePKCS7Padding(decryptedBytes), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException ex) {
      decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    unencryptedTextArea.clear();
    unencryptedTextArea.setText(decryptedText);
  }

  public void loadKeyFile(ActionEvent e) {
    File keyFile = loadFile(e, "file containing the key");
    if (keyFile != null) {
      readFromAFile(keyFile, keyLoadArea);
    }
  }

  public void loadUnencryptedFile(ActionEvent e) {
    File unecryptedFile = loadFile(e, "an unencrypted file");
    if (unecryptedFile != null) {
      unencryptedWindowBuffer = readFromAFile(unecryptedFile, unencryptedTextArea, openUnencryptedField);
    }
  }

  public void loadEncryptedFile(ActionEvent e) {
    File encryptedFile = loadFile(e, "an encrypted file");
    if (encryptedFile != null) {
      encryptedWindowBuffer = readFromAFile(encryptedFile, encryptedTextArea, openEncryptedField);
      System.out.println(encryptedWindowBuffer.length);
    }
  }

  public void saveKeyFile(ActionEvent e) {
    File keyFile = saveFile(e, "file to contain the key");
    if (keyFile != null) {
      writeToFile(keyFile, keySaveArea);
    }
  }

  public void saveUnencryptedFile(ActionEvent e) {
    File unecryptedFile = saveFile(e, "a file to contain the" +
                                              " unencrypted file");
    if (unecryptedFile != null) {
      if(!unecryptedFile.exists()) {
        try {
          unecryptedFile.createNewFile();
        } catch (IOException ex) {
          throw new RuntimeException(ex);
        }
      }
      writeToFile(unecryptedFile, unencryptedTextArea, saveUnencryptedField, unencryptedWindowBuffer);
    }
  }

  public void saveEncryptedFile(ActionEvent e) {
    File encryptedFile = saveFile(e, "a file to contain the" +
                                             " encrypted file");
    if (encryptedFile!= null) {
      writeToFile(encryptedFile, encryptedTextArea, saveEncryptedField, encryptedWindowBuffer);
    }
  }

  public File loadFile(ActionEvent event, final String fileType) {
    FileChooser fileChooser = new FileChooser();
    fileChooser.setTitle("Open " + fileType);
    return fileChooser.showOpenDialog( ((Button) event.getSource()).getScene().getWindow());
  }

  public File saveFile(ActionEvent event, final String fileType) {
    FileChooser fileChooser = new FileChooser();
    fileChooser.setTitle("Open " + fileType);
    return fileChooser.showSaveDialog(((Button) event.getSource()).getScene().getWindow());
  }

  private void showError(String header, String errorMessage) {
    Alert alert = new Alert(Alert.AlertType.ERROR);
    alert.setTitle("Error");
    alert.setHeaderText(header);
    alert.setContentText(errorMessage);

    alert.showAndWait();
  }

  public void readFromAFile(final File file, TextArea textArea) {

    try (FileInputStream fileInputStream = new FileInputStream(file)) {
      textArea.clear();
      byte[] buffer = new byte[1024];
      int bytesRead;
      while ((bytesRead = fileInputStream.read(buffer)) != -1) {
        textArea.appendText(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
      }
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }

  }

  public byte[] readFromAFile(final File file, TextArea textArea, TextField textField) {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(1024 * 1024 * 100);

    try (FileInputStream fileInputStream = new FileInputStream(file)) {
      textField.clear();
      textField.appendText(file.getAbsolutePath());
      textArea.clear();
      byte[] buffer = new byte[1024];
      int bytesRead;
      while ((bytesRead = fileInputStream.read(buffer)) != -1) {
        textArea.appendText(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
        byteArrayOutputStream.write(buffer, 0, bytesRead);
      }
    } catch (FileNotFoundException ex) {
      throw new RuntimeException(ex);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }

    return byteArrayOutputStream.toByteArray();
  }

  public void writeToFile(final File file, TextArea textArea) {
    try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
      byte[] data = textArea.getText().getBytes(StandardCharsets.UTF_8);
      fileOutputStream.write(data);
    } catch (FileNotFoundException ex) {
      throw new RuntimeException(ex);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }

  public void writeToFile(final File file, TextArea textArea, TextField textField, final byte[] buffer) {
    try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
      textField.clear();
      textField.appendText(file.getAbsolutePath());
      fileOutputStream.write(buffer);
    } catch (FileNotFoundException ex) {
      throw new RuntimeException(ex);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }
}
