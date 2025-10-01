
def count_longer_numerators(limit):

    count = 0

    # The first expansion: numerator = 3, denominator = 2

    numerator = 3

    denominator = 2
 
    for _ in range(2, limit + 1):

        # Next numerator and denominator

        numerator, denominator = numerator + 2 * denominator, numerator + denominator

        if len(str(numerator)) > len(str(denominator)):

            count += 1

    return count
 
if __name__ == "__main__":

    limit = 1000

    result = count_longer_numerators(limit)

    print(f"In the first {limit} expansions, there are {result} fractions with a numerator having more digits than denominator.")
 
