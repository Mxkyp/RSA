module view {
  requires javafx.fxml;
  requires javafx.graphics;
  requires javafx.controls;
  requires java.desktop;
  requires Logic;

  exports mainView;
  opens mainView;
}