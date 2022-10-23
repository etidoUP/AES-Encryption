package com.etido.aes_encryption;

import android.view.View;
import androidx.appcompat.app.AppCompatActivity;
import android.os.*;
import android.util.Log;
import android.content.Context;
import android.widget.Toast;
import com.etido.crypto.Basic.AESCrypto;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

public class MainActivity extends AppCompatActivity {

  private TextInputLayout til_enter_text;
  private TextInputLayout til_cipher;
  private TextInputLayout til_salt;
  private TextInputEditText et_enter_text;
  private TextInputEditText et_cipher;
  private TextInputEditText et_salt;
  private MaterialButton materialbutton1, materialbutton2;

  @Override
  protected void onCreate(Bundle savedInstanceState) {

    super.onCreate(savedInstanceState);
    // inflate view
    setContentView(R.layout.activity_main);
    til_enter_text = findViewById(R.id.til_enter_text);
    til_cipher = findViewById(R.id.til_cipher);
    til_salt = findViewById(R.id.til_salt);
    et_enter_text = findViewById(R.id.et_enter_text);
    et_cipher = findViewById(R.id.et_cipher);
    et_salt = findViewById(R.id.et_salt);
    materialbutton1 = findViewById(R.id.materialbutton1);
    materialbutton2 = findViewById(R.id.materialbutton2);

    // on click encrypt text
    materialbutton1.setOnClickListener(
        new View.OnClickListener() {
          @Override
          public void onClick(View mView) {
            et_cipher.setText(Encrypt(et_enter_text.getText().toString()));
          }
        });

    // on click decrypt text
    materialbutton2.setOnClickListener(
        new View.OnClickListener() {
          @Override
          public void onClick(View mView) {
            et_enter_text.setText(Decrypt(et_cipher.getText().toString()));
          }
        });
  }

  public String Encrypt(final String mValue) {
    String i = AESCrypto.EncodeText(mValue);
    et_cipher.setText(AESCrypto.mCipher);
    et_salt.setText(AESCrypto.getSaltKey);
    return i;
  }

  public String Decrypt(final String mdecipher) {
    String o = AESCrypto.DecodeText(mdecipher);
    et_enter_text.setText(AESCrypto.Decipher);
    return o;
  }
}
