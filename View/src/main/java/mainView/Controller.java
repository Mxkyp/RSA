package mainView;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import main.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Controller {

  //radio buttons
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

  @FXML TextField saveUnencryptedField;
  @FXML TextField saveEncryptedField;

  //Key gen elements
  @FXML TextField pubKeyGenField;
  @FXML TextField privKeyGenField;
  @FXML TextField modNKeyField;

  @FXML Button encryptBtn;
  @FXML Button decryptBtn;

  @FXML RadioButton size512;
  @FXML RadioButton size1024;
  @FXML RadioButton size2048;

  private byte[] unencryptedWindowBuffer;
  private byte[] encryptedWindowBuffer;
  private boolean defaultOutputSelection = true;

  private RSAKeyPair keyPair;
  private int keyBitSize = 512;

  /***
   Selects the button that is clicked and unselects all others.
   Updates the wanted keyLength accordingly
   * @param e event - pressing any of the 3 radio buttons
   */
  public void manageSizeButtons(ActionEvent e) {
    RadioButton[] sizeRadioButtons = {size512, size1024, size2048};
    RadioButton pressed = (RadioButton) e.getSource();

    switch(pressed.getId()) {
      case "size512":
        keyBitSize = 512;
        break;
      case "size1024":
        keyBitSize = 1024;
        break;
      case "size2048":
        keyBitSize = 2048;
        break;
    }

    for (RadioButton button: sizeRadioButtons) {
      if (!button.equals(pressed)) {
        button.setSelected(false);
      }
    }
  }

  /***
   * creates and saves key information based on user selection
   * @param e clicking the 'generate key' button
   */
  public void createKey(ActionEvent e) {
    keyPair = RSAKeyGenerator.generateKeyPair(keyBitSize);
    pubKeyGenField.setText(keyPair.getPublicKey().getE().toString(16));
    privKeyGenField.setText(keyPair.getPrivateKey().getD().toString(16));
    modNKeyField.setText(keyPair.getPublicKey().getN().toString(16));
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

  public void encrypt(ActionEvent e) throws Exception {

    if(defaultOutputSelection) {
      encryptBasedOnLoadedFiles();
    } else {
      encryptBasedOnWindows();
    }

  }

  public void encryptBasedOnLoadedFiles() throws Exception {
    if(unencryptedWindowBuffer == null) {
      showError("Load a unencrypted file!", "No file was loaded");
      return;
    }

    byte[] encryptedBytes = RSAEncryptor.encryptMessage(unencryptedWindowBuffer, keyPair.getPublicKey());

    encryptedWindowBuffer = encryptedBytes;

    encryptedTextArea.clear();
    encryptedTextArea.appendText(Utils.bytesToHex(encryptedBytes));
  }

  public void encryptBasedOnWindows() throws Exception {
    String text = unencryptedTextArea.getText();
    String encrypted = Utils.bytesToHex(RSAEncryptor.encryptMessage(text.getBytes(StandardCharsets.UTF_8), keyPair.getPublicKey()));

    encryptedTextArea.clear();
    encryptedTextArea.appendText(encrypted);
  }

  public void decrypt(ActionEvent e) throws Exception {
    if(defaultOutputSelection){
      decryptBasedOnLoadedFiles();
    } else {
      decryptBasedOnWindows();
    }
  }

  public void decryptBasedOnLoadedFiles() throws Exception {
    if(encryptedWindowBuffer == null) {
      showError("Load a encrypted file!", "No file was loaded");
      return;
    }

    byte[] decryptedBytes = RSADecryptor.decryptMessage(encryptedWindowBuffer, keyPair.getPrivateKey());

    String decryptedText;
    decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
    unencryptedWindowBuffer = decryptedBytes;

    unencryptedTextArea.clear();
    unencryptedTextArea.setText(decryptedText);
  }

  public void decryptBasedOnWindows() throws Exception {
    String text = encryptedTextArea.getText();

    byte[] decryptedBytes = RSADecryptor.decryptMessage(Utils.hexToBytes(text), keyPair.getPrivateKey());  //TODO:

    String decryptedText;
    decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

    unencryptedTextArea.clear();
    unencryptedTextArea.setText(decryptedText);
  }

  public void loadKeyFile(ActionEvent e) {
    File keyFile = loadFile(e, "file containing the key");
    if (keyFile != null) {
     readKeys(keyFile);
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
      writeKeys(keyFile);
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

  public void writeKeys(final File file) {
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      writer.write(pubKeyGenField.getText());
      writer.newLine();
      writer.write(privKeyGenField.getText());
      writer.newLine();
      writer.write(modNKeyField.getText());
    } catch (FileNotFoundException ex) {
      throw new RuntimeException(ex);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }

  public void readKeys(final File file) {
    try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
      String e = reader.readLine();
      String d = reader.readLine();
      String n = reader.readLine();
      RSAPublicKey publicKey = new RSAPublicKey(new BigInteger(n, 16), new BigInteger(e,16));
      RSAPrivateKey privateKey = new RSAPrivateKey(new BigInteger(n, 16), new BigInteger(d,16));
      keyPair = new RSAKeyPair(publicKey, privateKey);

      pubKeyGenField.setText(keyPair.getPublicKey().getE().toString(16));
      privKeyGenField.setText(keyPair.getPrivateKey().getD().toString(16));
      modNKeyField.setText(keyPair.getPublicKey().getN().toString(16));
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
