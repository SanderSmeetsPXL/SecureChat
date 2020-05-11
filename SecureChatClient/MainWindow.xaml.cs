using Microsoft.Win32;
using SecureChatLib.net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

namespace SecureChatClient
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

        private bool _autoScroll = true;
        public ChatClient ChatClient { get; set; }

        private void ScrollViewer_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (e.ExtentHeightChange == 0)
            {
                _autoScroll = ScrollViewer.VerticalOffset == ScrollViewer.ScrollableHeight;
            }

            if (_autoScroll && e.ExtentHeightChange != 0)
            {
                ScrollViewer.ScrollToVerticalOffset(ScrollViewer.ExtentHeight);
            }
        }

        private async void ConnectionButton_Click(object sender, RoutedEventArgs e)
        {
            ChatClient = new ChatClient();
            if (await ChatClient.ConnectAsync("localhost", 8564))
            {
                ChatClient.sendPublicKeyServer();
                WriteMessageToChatBox();
                chatBox.Text += "---CONNECTED: please choose an username...\n";
                LoginForm loginForm = new LoginForm();
                loginForm.ShowDialog();
                ChatClient.SendLoginCredentials();
                connectionButton.IsEnabled = false;
                sendMessageBox.IsEnabled = true;
                sendFileButton.IsEnabled = true;
            }
            else
            {
                chatBox.Text += "---ERROR: connection failed.\n";
            }
        }

        private async void WriteMessageToChatBox()
        {
            while (true)
            {
                string message = await ChatClient.ReadDataAsync();
                chatBox.Text += message + "\n";
            }
        }

        private void OnPressEnter(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Return)
            {
                ChatClient.SendChatMessage(sendMessageBox.Text);
                chatBox.Text += "(" + ChatClient.Username + "): " + sendMessageBox.Text + "\n";
                sendMessageBox.Text = "";
            }
        }

        private void SendFileButton_Click(object sender, RoutedEventArgs e)
        {
            SelectUserDialog selectUserDialog = new SelectUserDialog(ChatClient.onlineUsernames);
            selectUserDialog.ShowDialog();
            Guid selectedUserId = selectUserDialog.selectedId;

            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.ShowDialog();
            string filePath = openFileDialog.FileName;

            chatBox.Text += "---Sending file.";
            ChatClient.SendFileMessage(selectedUserId, System.IO.Path.GetFileName(filePath), File.ReadAllBytes(filePath));
        }
    }
}
