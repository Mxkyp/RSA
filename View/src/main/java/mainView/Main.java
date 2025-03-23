package mainView;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.scene.paint.Color;
import javafx.stage.Stage;

public final class Main extends Application {

  public static void main(final String[] args) {
    launch(args);
  }

  @Override
  public void start(Stage stage) throws Exception {
    Parent root = FXMLLoader.load(getClass().getResource("/fxml/main.fxml"));
    Scene scene = new Scene(root, Color.BISQUE);
    //Image icon = new Image(getClass().getResource("/images/sudoku.png").toExternalForm());
    //stage.getIcons().add(icon);

    stage.setTitle("AES Algorithm example");
    stage.setResizable(false);
    stage.setScene(scene);
    stage.show();
  }
}
