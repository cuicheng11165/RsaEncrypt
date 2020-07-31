using Gao.Util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Tool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var cert = LoadCertificate(this.text_thrumbprint.Text.Trim());

            var _encryptionHelper = new RandomKeyEncryptionHelper(cert);
            this.text2.Text = _encryptionHelper.EncryptString(this.text1.Text);
        }

        private static X509Certificate2 LoadCertificate(String thumbprint)
        {

            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var vCloudCertificate = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    false)[0];
            return vCloudCertificate;
        }

        private void btn_de_Click(object sender, RoutedEventArgs e)
        {
            var cert = LoadCertificate(this.text_thrumbprint.Text.Trim());

            var _encryptionHelper = new RandomKeyEncryptionHelper(cert);
            this.text2.Text = _encryptionHelper.DecryptString(this.text1.Text);
        }
    }
}
