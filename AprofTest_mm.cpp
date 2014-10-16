typedef int Fixed;

void mm(Fixed a[2][2], Fixed b[2][2], Fixed o[2][2])
{
	for (int r = 0; r < 2; ++r)
	{
		for (int c = 0; c < 2; ++c)
		{
			Fixed t = 0;
			for (int i = 0; i < 2; ++i)
			{
				t += (a[r][i] * b[i][c] + 32768) >> 16;
			}
			o[r][c] = t;
		}
	}
}