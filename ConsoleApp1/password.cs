using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Pingfu.Security
{
    /// <summary>
    /// PasswordGenerator
    /// </summary>
    public class Password
    {
        private const string PasswordCharsLcase = "abcdefgijkmnpqrstwxyz";
        private const string PasswordCharsUcase = "ABCDEFGHJKLMNPQRSTWXYZ";
        private const string PasswordCharsNumeric = "123456789";
        private const string PasswordCharsSpecial = "ABCDEFGHJKLMNPQRSTWXYZabcdefgijkmnpqrstwxyz123456789";

        /// <summary>
        /// 
        /// </summary>
        /// <param name="quantity"></param>
        /// <param name="minLength"></param>
        /// <param name="maxLength"></param>
        /// <returns></returns>
        public static List<string> Generate(int quantity, int minLength, int maxLength)
        {
            var passwords = new List<string>();
            for (var i = 0; i < quantity; i++)
            {
                passwords.Add(Generate(16, 18));
            }
            return passwords;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="minLength"></param>
        /// <param name="maxLength"></param>
        /// <returns></returns>
        public static string Generate(int minLength, int maxLength)
        {
            if (minLength <= 0 || maxLength <= 0 || minLength > maxLength)
            {
                return null;
            }           

            // Create a local array containing supported password characters grouped by types. 
            // You can remove character groups from this array, but doing so will weaken the password strength.        
            var charGroups = new []
            {
                PasswordCharsLcase.ToCharArray(),
                PasswordCharsUcase.ToCharArray(),
                PasswordCharsNumeric.ToCharArray(),
                PasswordCharsSpecial.ToCharArray()
            };

            // Use this array to track the number of unused characters in each character group.
            var charsLeftInGroup = new int[charGroups.Length];

            // Initially, all characters in each group are not used.
            for (var i = 0; i < charsLeftInGroup.Length; i++)
            {
                charsLeftInGroup[i] = charGroups[i].Length;
            }           

            // Use this array to track (iterate through) unused character groups.
            var leftGroupsOrder = new int[charGroups.Length];

            // Initially, all character groups are not used.
            for (int i = 0; i < leftGroupsOrder.Length; i++)
            {
                leftGroupsOrder[i] = i;
            }

            // Because we cannot use the default randomizer, which is based on the current time 
            // (it will produce the same "random" number within a second), we will use a random number 
            // generator to seed the randomizer. Use a 4-byte array to fill it with random bytes and convert
            // it then to an integer value.
            var randomBytes = new byte[4];

            // Generate 4 random bytes.
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomBytes);

            // Convert 4 bytes into a 32-bit integer value.
            var seed = (randomBytes[0] & 0x7f) << 24 |
                       randomBytes[1] << 16 |
                       randomBytes[2] << 8 |
                       randomBytes[3];

            // Now, this is real randomization.
            var random = new Random(seed);

            // This array will hold password characters.
            // Allocate appropriate memory for the password.
            var password = minLength < maxLength ? new char[random.Next(minLength, maxLength + 1)] : new char[minLength];

            // some indexes
            var lastLeftGroupsOrderIdx = leftGroupsOrder.Length - 1;

            // Generate password characters one at a time.
            for (var i = 0; i < password.Length; i++)
            {
                // If only one character group remained unprocessed, process it; otherwise, 
                // pick a random character group from the unprocessed group list. To allow a 
                // special character to appear in the first position, increment the second 
                // parameter of the Next function call by one, i.e. lastLeftGroupsOrderIdx + 1.
                var nextLeftGroupsOrderIdx = lastLeftGroupsOrderIdx == 0 ? 0 : random.Next(0, lastLeftGroupsOrderIdx);

                // Get the actual index of the character group, from which we will pick the next character.
                var nextGroupIdx = leftGroupsOrder[nextLeftGroupsOrderIdx];
                var lastCharIdx = charsLeftInGroup[nextGroupIdx] - 1;

                // If only one unprocessed character is left, pick it; otherwise, get a 
                // random character from the unused character list.
                var nextCharIdx = lastCharIdx == 0 ? 0 : random.Next(0, lastCharIdx + 1);

                // Add this character to the password.
                password[i] = charGroups[nextGroupIdx][nextCharIdx];

                // If we processed the last character in this group, start over.
                if (lastCharIdx == 0)
                {
                    charsLeftInGroup[nextGroupIdx] = charGroups[nextGroupIdx].Length;
                }
                else
                {
                    if (lastCharIdx != nextCharIdx)
                    {
                        var temp = charGroups[nextGroupIdx][lastCharIdx];
                        charGroups[nextGroupIdx][lastCharIdx] = charGroups[nextGroupIdx][nextCharIdx];
                        charGroups[nextGroupIdx][nextCharIdx] = temp;
                    }
                    charsLeftInGroup[nextGroupIdx]--;
                }

                // If we processed the last group, start all over.
                if (lastLeftGroupsOrderIdx == 0)
                {
                    lastLeftGroupsOrderIdx = leftGroupsOrder.Length - 1;
                }
                else
                {
                    // Swap processed group with the last unprocessed group so that we don't pick it until we process all groups.
                    if (lastLeftGroupsOrderIdx != nextLeftGroupsOrderIdx)
                    {
                        var temp = leftGroupsOrder[lastLeftGroupsOrderIdx];
                        leftGroupsOrder[lastLeftGroupsOrderIdx] = leftGroupsOrder[nextLeftGroupsOrderIdx];
                        leftGroupsOrder[nextLeftGroupsOrderIdx] = temp;
                    }

                    // Decrement the number of unprocessed groups.
                    lastLeftGroupsOrderIdx--;
                }
            }

            // Convert password characters into a string and return the result.
            return new string(password);
        }
    }
}
 