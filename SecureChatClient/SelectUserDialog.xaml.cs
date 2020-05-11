using System;
using System.Collections.Generic;
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
using System.Windows.Shapes;

namespace SecureChatClient
{
    /// <summary>
    /// Interaction logic for SelectUserDialog.xaml
    /// </summary>
    public partial class SelectUserDialog : Window
    {
        private List<KeyValuePair<Guid, string>> usernamePairs;
        public Guid selectedId;
        public SelectUserDialog(Dictionary<Guid, string> usernames)
        {
            InitializeComponent();
            usernamePairs = usernames.ToList();
            foreach (KeyValuePair<Guid, string> pair in usernamePairs)
            {
                SelectUserList.Items.Add(pair.Value);
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            selectedId = usernamePairs[SelectUserList.SelectedIndex].Key;
            this.Close();
        }
    }
}
